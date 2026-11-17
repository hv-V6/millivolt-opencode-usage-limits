package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func validManifest() string {
	return fmt.Sprintf(`{
		"id":"error-analyzer",
		"version":"0.1.0",
		"abi":"v1",
		"min_millivolt":"0.3.26",
		"capabilities":["log","emit_metric"],
		"module":"analyzer.wasm",
		"module_sha256":%q,
		"license":"MIT"
	}`, hash("module"))
}

func TestValidManifest(t *testing.T) {
	m, err := Parse([]byte(validManifest()))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Has("emit_metric") || m.Has("read:records") {
		t.Fatalf("capabilities = %v", m.Capabilities)
	}
}

func TestInvalidManifests(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"wrong abi", strings.Replace(validManifest(), `"abi":"v1"`, `"abi":"v2"`, 1), "abi:"},
		{"unknown capability", strings.Replace(validManifest(), `"emit_metric"`, `"read:everything"`, 1), "unknown"},
		{"bad hash", strings.Replace(validManifest(), hash("module"), "xyz", 1), "module_sha256:"},
		{"trailing", validManifest() + " {}", "trailing JSON"},
		{"unknown field", strings.Replace(validManifest(), `"license":"MIT"`, `"license":"MIT","x":1`, 1), "unknown field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSigningPayloadAndSign(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse([]byte(validManifest()))
	if err != nil {
		t.Fatal(err)
	}
	before := string(m.SigningPayload())
	if err := m.Sign("release", priv); err != nil {
		t.Fatal(err)
	}
	if string(m.SigningPayload()) != before {
		t.Fatal("SigningPayload changed when signing")
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(pub, m.SigningPayload(), sig) {
		t.Fatalf("signature did not verify: %v", err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := Parse(raw)
	if err != nil || reparsed.Signer != "release" {
		t.Fatalf("signed manifest did not round-trip: %+v, %v", reparsed, err)
	}
}
