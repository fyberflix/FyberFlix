package httpapi

import (
	"errors"
	"io"
	"net/http"
)

const (
	maxFrames     = 24
	maxFrameBytes = 600_000
	maxFormBytes  = 16 << 20
)

var errBadForm = errors.New("bad form")

type form struct {
	fields map[string]string
	frames [][]byte
}

// readForm streams a multipart body: text fields (<=256 bytes) and up to 24 JPEG "frames".
func readForm(w http.ResponseWriter, r *http.Request) (*form, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, errBadForm
	}
	f := &form{fields: map[string]string{}}
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return f, nil
		}
		if err != nil {
			return nil, errBadForm
		}
		switch {
		case p.FormName() == "frames" && p.FileName() != "":
			if len(f.frames) >= maxFrames {
				return nil, errBadForm
			}
			b, err := io.ReadAll(io.LimitReader(p, maxFrameBytes+1))
			if err != nil || len(b) > maxFrameBytes || len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 || b[2] != 0xFF {
				return nil, errBadForm // frames must be JPEG
			}
			f.frames = append(f.frames, b)
		case p.FileName() == "":
			b, err := io.ReadAll(io.LimitReader(p, 257))
			if err != nil || len(b) > 256 {
				return nil, errBadForm
			}
			f.fields[p.FormName()] = string(b)
		default:
			return nil, errBadForm
		}
	}
}
