// Command ariguard-ctl is the operator CLI for the control plane. Today it signs and pushes policy
// bundles (C2): the rule-generation pipeline produces a bundle, signs it with the ed25519 private
// key, and PUTs it to the console with a detached signature header; agents carry only the public key
// and verify before loading it into the kernel.
//
//	ariguard-ctl keygen --out ariguard-policy          # writes ariguard-policy.key (private) + .pub
//	ariguard-ctl policy sign --key k.key bundle.bin    # prints the base64 signature
//	ariguard-ctl policy push --url http://console:8080 --token "$TOK" --key k.key bundle.bin
package main

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/CosminMilica/ariguard/pkg/fsm"
)

// newFlagSet returns a flag set that reports parse errors (and -h) through the returned error rather
// than exiting, so run() can surface them uniformly.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ariguard-ctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:])
	case "policy":
		if len(args) < 2 {
			return usage()
		}
		switch args[1] {
		case "sign":
			return policySign(args[2:])
		case "push":
			return policyPush(args[2:])
		}
		return usage()
	}
	return usage()
}

func usage() error {
	return fmt.Errorf("usage: ariguard-ctl <keygen|policy sign|policy push> [flags] [bundle]\n" +
		"  keygen --out <prefix>                writes <prefix>.key (private) and <prefix>.pub (public)\n" +
		"  policy sign --key <file> <bundle>    prints the base64 ed25519 signature of the bundle\n" +
		"  policy push --url <u> [--token t] --key <file> <bundle>   signs and PUTs /api/v1/policy")
}

// --- keygen ----------------------------------------------------------------------------------

func keygen(args []string) error {
	var out string
	fs := newFlagSet("keygen")
	fs.StringVar(&out, "out", "ariguard-policy", "output path prefix (<prefix>.key / <prefix>.pub)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := fsm.GenerateSigningKey()
	if err != nil {
		return err
	}
	// The private key is sensitive: write it 0600.
	if err := os.WriteFile(out+".key", []byte(fsm.MarshalPrivateKey(priv)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(out+".pub", []byte(fsm.MarshalPublicKey(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s.key (private, keep secret) and %s.pub (public, give to agents)\n", out, out)
	return nil
}

// --- policy sign -----------------------------------------------------------------------------

func policySign(args []string) error {
	var keyFile string
	fs := newFlagSet("policy sign")
	fs.StringVar(&keyFile, "key", "", "ed25519 private key file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, bundle, err := loadKeyAndBundle(keyFile, fs.Args())
	if err != nil {
		return err
	}
	fmt.Println(fsm.EncodeSignature(fsm.SignBundle(priv, bundle)))
	return nil
}

// --- policy push -----------------------------------------------------------------------------

func policyPush(args []string) error {
	var keyFile, url, token string
	fs := newFlagSet("policy push")
	fs.StringVar(&keyFile, "key", "", "ed25519 private key file (required)")
	fs.StringVar(&url, "url", "", "console base URL, e.g. http://console:8080 (required)")
	fs.StringVar(&token, "token", "", "control-plane bearer token (or set ARIGUARD_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if url == "" {
		return fmt.Errorf("--url is required")
	}
	if token == "" {
		token = os.Getenv("ARIGUARD_TOKEN")
	}
	priv, bundle, err := loadKeyAndBundle(keyFile, fs.Args())
	if err != nil {
		return err
	}
	sig := fsm.SignBundle(priv, bundle)

	req, err := http.NewRequest(http.MethodPut, trimURL(url)+"/api/v1/policy", bytes.NewReader(bundle))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Policy-Signature", fsm.EncodeSignature(sig))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("PUT /api/v1/policy: status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	fmt.Printf("pushed signed bundle (%d bytes), version %s\n", len(bundle), resp.Header.Get("X-Policy-Version"))
	return nil
}

// --- helpers ---------------------------------------------------------------------------------

func loadKeyAndBundle(keyFile string, rest []string) (priv ed25519.PrivateKey, bundle []byte, err error) {
	if keyFile == "" {
		return nil, nil, fmt.Errorf("--key is required")
	}
	if len(rest) != 1 {
		return nil, nil, fmt.Errorf("expected exactly one bundle file argument")
	}
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read key: %w", err)
	}
	p, err := fsm.ParsePrivateKey(string(keyBytes))
	if err != nil {
		return nil, nil, err
	}
	bundle, err = os.ReadFile(rest[0])
	if err != nil {
		return nil, nil, fmt.Errorf("read bundle: %w", err)
	}
	if len(bundle) == 0 {
		return nil, nil, fmt.Errorf("bundle %s is empty", rest[0])
	}
	return p, bundle, nil
}

func trimURL(u string) string {
	for len(u) > 0 && u[len(u)-1] == '/' {
		u = u[:len(u)-1]
	}
	return u
}
