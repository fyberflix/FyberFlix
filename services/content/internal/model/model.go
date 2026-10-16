// Package model holds the plain data types shared by the API, the store and the worker.
package model

import (
	"errors"
	"time"
)

const (
	StatusAwaitingUpload = "awaiting_upload"
	StatusProcessing     = "processing"
	StatusReady          = "ready"
	StatusFailed         = "failed"
	StatusRemoved        = "removed"

	KindReel  = "reel"
	KindVideo = "video"

	VisPublic   = "public"
	VisUnlisted = "unlisted"
	VisPrivate  = "private"

	JobTranscode = "transcode"
	JobPurge     = "purge"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict: wrong state")
)

type Video struct {
	ID             string
	OwnerID        string
	Kind           string
	Status         string
	Caption        string
	Visibility     string
	SrcKey         string
	SrcContentType string
	SrcBytes       int64
	DurationMS     int
	Width          int
	Height         int
	HLSKey         string
	ThumbKey       string
	MediaKeys      []string
	FailReason     string
	CreatedAt      time.Time
	PublishedAt    *time.Time
}

// Cursor is a keyset position for newest-first listings.
type Cursor struct {
	At time.Time
	ID string
}

type Job struct {
	ID          int64
	Kind        string
	VideoID     string
	Attempts    int
	MaxAttempts int
}

// Result is what the worker learned and produced for a video.
type Result struct {
	DurationMS int
	Width      int
	Height     int
	HLSKey     string
	ThumbKey   string
	MediaKeys  []string
}
