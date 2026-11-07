package fsm

import (
	"crypto/ed25519"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("a policy bundle")
	sig := SignBundle(priv, bundle)
	if !VerifyBundle(pub, bundle, sig) {
		t.Fatal("valid signature should verify")
	}
}

func TestVerifyRejectsTamperedBundle(t *testing.T) {
	pub, priv, _ := GenerateSigningKey()
	bundle := []byte("original bundle bytes")
	sig := SignBundle(priv, bundle)
	tampered := append([]byte(nil), bundle...)
	tampered[0] ^= 0xff
	if VerifyBundle(pub, tampered, sig) {
		t.Fatal("tampered bundle must not verify")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := GenerateSigningKey()
	otherPub, _, _ := GenerateSigningKey()
	bundle := []byte("bundle")
	sig := SignBundle(priv, bundle)
	if VerifyBundle(otherPub, bundle, sig) {
		t.Fatal("signature must not verify under an unrelated public key")
	}
}

func TestVerifyRejectsMalformedSizes(t *testing.T) {
	pub, priv, _ := GenerateSigningKey()
	bundle := []byte("bundle")
	sig := SignBundle(priv, bundle)
	if VerifyBundle(pub, bundle, sig[:len(sig)-1]) {
		t.Fatal("short signature must not verify")
	}
	if VerifyBundle(ed25519.PublicKey("short"), bundle, sig) {
		t.Fatal("undersized public key must not verify")
	}
}

func TestKeyEncodingRoundTrip(t *testing.T) {
	pub, priv, _ := GenerateSigningKey()
	gotPub, err := ParsePublicKey(MarshalPublicKey(pub))
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("public key round-trip: %v", err)
	}
	gotPriv, err := ParsePrivateKey(MarshalPrivateKey(priv))
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private key round-trip: %v", err)
	}
	// a signature from the parsed key still verifies under the parsed public key
	sig := SignBundle(gotPriv, []byte("x"))
	if !VerifyBundle(gotPub, []byte("x"), sig) {
		t.Fatal("round-tripped keys should interoperate")
	}
}

func TestParseKeyRejectsWrongLength(t *testing.T) {
	if _, err := ParsePublicKey("YWJj"); err == nil { // "abc" -> 3 bytes, not 32
		t.Fatal("expected error for wrong-length public key")
	}
	if _, err := ParsePrivateKey("not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64 private key")
	}
}

func TestSignatureEncodingRoundTrip(t *testing.T) {
	_, priv, _ := GenerateSigningKey()
	sig := SignBundle(priv, []byte("x"))
	got, err := DecodeSignature(EncodeSignature(sig))
	if err != nil || string(got) != string(sig) {
		t.Fatalf("signature encoding round-trip: %v", err)
	}
}
