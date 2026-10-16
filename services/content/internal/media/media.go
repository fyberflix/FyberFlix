// Package media validates untrusted uploads and turns them into HLS renditions with ffmpeg.
package media

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	MaxDim        = 4096
	MaxStreams    = 8
	MaxReelMS     = 90_000
	MaxVideoMS    = 30 * 60_000
	minShortSide  = 360
	hlsSegmentSec = 4
)

// Sniff checks the magic bytes and returns the ffmpeg demuxer list to force ("" = reject).
func Sniff(head []byte) string {
	if len(head) >= 12 && string(head[4:8]) == "ftyp" {
		return "mov,mp4,m4a,3gp,3g2,mj2"
	}
	if len(head) >= 4 && bytes.Equal(head[:4], []byte{0x1A, 0x45, 0xDF, 0xA3}) {
		return "matroska,webm"
	}
	return ""
}

type Info struct {
	DurationMS    int
	Width, Height int // after rotation
	HasAudio      bool
}

type probeJSON struct {
	Streams []struct {
		CodecType string            `json:"codec_type"`
		Width     int               `json:"width"`
		Height    int               `json:"height"`
		Tags      map[string]string `json:"tags"`
		SideData  []struct {
			Rotation float64 `json:"rotation"`
		} `json:"side_data_list"`
		Disposition struct {
			AttachedPic int `json:"attached_pic"`
		} `json:"disposition"`
	} `json:"streams"`
	Format struct {
		Duration string `json:"duration"`
	} `json:"format"`
}

// ParseProbe validates ffprobe JSON output. kind is "reel" or "video".
func ParseProbe(raw []byte, kind string) (Info, error) {
	var p probeJSON
	if err := json.Unmarshal(raw, &p); err != nil {
		return Info{}, errors.New("unreadable media")
	}
	if len(p.Streams) == 0 || len(p.Streams) > MaxStreams {
		return Info{}, errors.New("unsupported stream layout")
	}
	var in Info
	found := false
	for _, s := range p.Streams {
		switch s.CodecType {
		case "audio":
			in.HasAudio = true
		case "video":
			if s.Disposition.AttachedPic == 1 || found {
				continue
			}
			found = true
			w, h := s.Width, s.Height
			rot := 0.0
			if v, ok := s.Tags["rotate"]; ok {
				rot, _ = strconv.ParseFloat(v, 64)
			}
			for _, sd := range s.SideData {
				if sd.Rotation != 0 {
					rot = sd.Rotation
				}
			}
			if r := int(rot); r%180 != 0 {
				w, h = h, w
			}
			in.Width, in.Height = w, h
		}
	}
	if !found || in.Width <= 0 || in.Height <= 0 {
		return Info{}, errors.New("no video stream")
	}
	if in.Width > MaxDim || in.Height > MaxDim {
		return Info{}, errors.New("resolution too large")
	}
	d, err := strconv.ParseFloat(p.Format.Duration, 64)
	if err != nil || d <= 0 {
		return Info{}, errors.New("unknown duration")
	}
	in.DurationMS = int(d * 1000)
	max := MaxVideoMS
	if kind == "reel" {
		max = MaxReelMS
	}
	if in.DurationMS > max+500 {
		return Info{}, fmt.Errorf("too long (max %ds)", max/1000)
	}
	return in, nil
}

type Rendition struct {
	Name      string // "720p", "360p" or "src"
	W, H      int
	VBitrate  int // bits/s, used in the master playlist
	Bandwidth int
}

func even(n int) int {
	if n%2 == 1 {
		return n - 1
	}
	return n
}

// PlanRenditions picks renditions by short side (720, 360), never upscaling.
func PlanRenditions(w, h int) []Rendition {
	short, long := w, h
	if h < w {
		short, long = h, w
	}
	scaled := func(target int) (int, int) {
		nl := even(long * target / short)
		if w <= h {
			return target, nl
		}
		return nl, target
	}
	var out []Rendition
	if short >= 720 {
		rw, rh := scaled(720)
		out = append(out, Rendition{"720p", rw, rh, 2_500_000, 2_700_000})
	}
	if short >= 360 {
		rw, rh := scaled(360)
		out = append(out, Rendition{"360p", rw, rh, 800_000, 900_000})
	}
	if len(out) == 0 {
		out = append(out, Rendition{"src", even(w), even(h), 600_000, 700_000})
	}
	return out
}

func MasterPlaylist(rs []Rendition) string {
	var b strings.Builder
	b.WriteString("#EXTM3U\n#EXT-X-VERSION:3\n")
	for _, r := range rs {
		fmt.Fprintf(&b, "#EXT-X-STREAM-INF:BANDWIDTH=%d,RESOLUTION=%dx%d\n%s/index.m3u8\n", r.Bandwidth, r.W, r.H, r.Name)
	}
	return b.String()
}

// Probe runs ffprobe with a forced demuxer.
func Probe(ctx context.Context, path, demuxer, kind string) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-f", demuxer,
		"-show_format", "-show_streams", "-of", "json", path).Output()
	if err != nil {
		return Info{}, errors.New("unreadable media")
	}
	return ParseProbe(out, kind)
}

// Transcode writes dir/master.m3u8, dir/<rendition>/index.m3u8 + segments, and dir/thumb.jpg.
func Transcode(ctx context.Context, src, demuxer, dir string, in Info, rs []Rendition) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	for _, r := range rs {
		od := filepath.Join(dir, r.Name)
		if err := os.MkdirAll(od, 0o700); err != nil {
			return err
		}
		args := []string{"-nostdin", "-v", "error", "-f", demuxer, "-i", src,
			"-map", "0:v:0", "-map", "0:a:0?", "-map_metadata", "-1", "-map_chapters", "-1",
			"-vf", fmt.Sprintf("scale=%d:%d,setsar=1", r.W, r.H),
			"-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p",
			"-c:a", "aac", "-b:a", "128k", "-ac", "2",
			"-sn", "-dn",
			"-f", "hls", "-hls_time", strconv.Itoa(hlsSegmentSec), "-hls_playlist_type", "vod",
			"-hls_segment_filename", filepath.Join(od, "seg_%04d.ts"),
			filepath.Join(od, "index.m3u8")}
		if out, err := exec.CommandContext(ctx, "ffmpeg", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ffmpeg %s: %v: %s", r.Name, err, tail(out))
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "master.m3u8"), []byte(MasterPlaylist(rs)), 0o600); err != nil {
		return err
	}
	at := float64(in.DurationMS) / 1000 / 3
	args := []string{"-nostdin", "-v", "error", "-f", demuxer, "-ss", fmt.Sprintf("%.2f", at), "-i", src,
		"-map", "0:v:0", "-frames:v", "1", "-map_metadata", "-1",
		"-vf", "scale='min(640,iw)':-2", "-q:v", "4", "-y", filepath.Join(dir, "thumb.jpg")}
	if out, err := exec.CommandContext(ctx, "ffmpeg", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ffmpeg thumb: %v: %s", err, tail(out))
	}
	return nil
}

func tail(b []byte) string {
	if len(b) > 400 {
		b = b[len(b)-400:]
	}
	return strings.TrimSpace(string(b))
}
