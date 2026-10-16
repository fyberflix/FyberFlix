// Command devtoken prints a short-lived access token for a fake user, signed with the auth key.
// DEV ONLY: lets you test uploads without the camera. Needs AUTH_JWT_SEED (and optionally AUTH_JWT_KID).
//
//	go run ./tools/devtoken [user-uuid]
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	seed, err := base64.StdEncoding.DecodeString(os.Getenv("AUTH_JWT_SEED"))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "AUTH_JWT_SEED must be base64 of 32 bytes")
		os.Exit(1)
	}
	kid := os.Getenv("AUTH_JWT_KID")
	if kid == "" {
		kid = "k1"
	}
	user := "11111111-1111-4111-8111-111111111111"
	if len(os.Args) > 1 {
		user = os.Args[1]
	}
	b64 := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	now := time.Now()
	cl, _ := json.Marshal(map[string]any{"iss": "fyberflix-auth", "aud": "fyberflix", "sub": user,
		"sid": "dev", "num": "000000000", "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix()})
	in := b64.EncodeToString(hdr) + "." + b64.EncodeToString(cl)
	fmt.Println(in + "." + b64.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(in))))
}
