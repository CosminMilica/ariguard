package fsm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// Policy-bundle signing (C2). The bundle the agent hot-swaps into the kernel must be authentic, not
// just well-formed: a stolen control-plane token (present on every node) or a compromised console
// could otherwise push a bundle that strips kill actions or whitelists an attacker's chain.
//
// We use ed25519 (asymmetric): the rule-generation pipeline signs with a PRIVATE key; agents carry
// only the PUBLIC key and verify. A compromised agent cannot forge a bundle (it has no signing key) —
// which is exactly why a symmetric MAC (shared secret on every node) would not help here. The
// signature is detached (carried in the X-Policy-Signature HTTP header), so the bundle format is
// unchanged and an agent without a configured public key stays backward-compatible.

// SignBundle returns the ed25519 signature of bundle under priv.
func SignBundle(priv ed25519.PrivateKey, bundle []byte) []byte {
	return ed25519.Sign(priv, bundle)
}

// VerifyBundle reports whether sig is a valid ed25519 signature of bundle under pub. It is
// constant-time in the crypto and defensive about key/signature sizes.
func VerifyBundle(pub ed25519.PublicKey, bundle, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, bundle, sig)
}

// GenerateSigningKey returns a fresh ed25519 keypair for signing policy bundles.
func GenerateSigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// MarshalPublicKey / MarshalPrivateKey encode a key as a single base64 line for a key file.
func MarshalPublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

func MarshalPrivateKey(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv)
}

// ParsePublicKey decodes a base64 ed25519 public key (whitespace tolerated).
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("fsm: decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("fsm: public key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey decodes a base64 ed25519 private key (whitespace tolerated).
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("fsm: decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("fsm: private key is %d bytes, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

// EncodeSignature / DecodeSignature carry the detached signature in the X-Policy-Signature header.
func EncodeSignature(sig []byte) string { return base64.StdEncoding.EncodeToString(sig) }

func DecodeSignature(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("fsm: decode signature: %w", err)
	}
	return b, nil
}
