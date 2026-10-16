// Package s3sign creates AWS Signature V4 pre-signed URLs (query authentication) for
// S3-compatible object stores (MinIO, AWS S3, Cloudflare R2). Standard library only.
package s3sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Creds struct {
	AccessKey string
	SecretKey string
	Region    string
}

// Presign returns a URL for method on endpoint/bucket/key that is valid for ttl.
// Path-style addressing is used (endpoint/bucket/key), which MinIO requires; pass an empty
// bucket to sign endpoint/key. Headers in signed (lower-case names) are part of the
// signature: the caller must send exactly those values. Host is always signed.
func (c Creds) Presign(method, endpoint, bucket, key string, ttl time.Duration, now time.Time, signed map[string]string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("s3sign: bad endpoint")
	}
	secs := int64(ttl / time.Second)
	if secs < 1 || secs > 604800 {
		return "", errors.New("s3sign: ttl must be 1s..7d")
	}
	if key == "" || strings.HasPrefix(key, "/") {
		return "", errors.New("s3sign: bad key")
	}
	path := "/" + key
	if bucket != "" {
		path = "/" + bucket + path
	}
	canonURI := encodePath(path)

	hdrs := map[string]string{"host": u.Host}
	for k, v := range signed {
		hdrs[strings.ToLower(k)] = strings.TrimSpace(v)
	}
	names := make([]string, 0, len(hdrs))
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k + ":" + hdrs[k] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	now = now.UTC()
	date := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")
	scope := date + "/" + c.Region + "/s3/aws4_request"
	q := map[string]string{
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Credential":    c.AccessKey + "/" + scope,
		"X-Amz-Date":          amzDate,
		"X-Amz-Expires":       strconv.FormatInt(secs, 10),
		"X-Amz-SignedHeaders": signedHeaders,
	}
	canonQuery := encodeQuery(q)

	canonReq := strings.Join([]string{method, canonURI, canonQuery, ch.String(), signedHeaders, "UNSIGNED-PAYLOAD"}, "\n")
	sum := sha256.Sum256([]byte(canonReq))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])

	k := hmacSHA([]byte("AWS4"+c.SecretKey), date)
	k = hmacSHA(k, c.Region)
	k = hmacSHA(k, "s3")
	k = hmacSHA(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(k, toSign))

	return u.Scheme + "://" + u.Host + canonURI + "?" + canonQuery + "&X-Amz-Signature=" + sig, nil
}

func hmacSHA(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func encodeQuery(q map[string]string) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, encode(k)+"="+encode(q[k]))
	}
	return strings.Join(parts, "&")
}

// encodePath percent-encodes every path segment, keeping "/" separators.
func encodePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = encode(s)
	}
	return strings.Join(segs, "/")
}

// encode is RFC 3986 encoding as AWS wants it: only A-Z a-z 0-9 - _ . ~ stay as they are.
func encode(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&15])
		}
	}
	return b.String()
}
