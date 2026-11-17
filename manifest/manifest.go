// Package manifest parses and validates plugin manifests.
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/LLM-4-People/millivolt-plugin-sdk/abi/v1"
)

const (
	MaxManifestBytes = 16 << 10
	MaxCapabilities  = 16
)

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	semverPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
	modulePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+\.wasm$`)
)

// Capabilities is the closed vocabulary a v1 plugin manifest may request.
// Names match the host imports in the ABI contract, not the operator-plane
// capability names; the host maps them when it grants a plugin token.
var Capabilities = []string{
	"log",
	"emit_metric",
	"read:records",
	"read:config",
	"declare_tool",
	"declare_ui_panel",
}

// Manifest is the complete install-time declaration for one plugin module.
type Manifest struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	ABI          string   `json:"abi"`
	MinMillivolt string   `json:"min_millivolt"`
	Capabilities []string `json:"capabilities"`
	Module       string   `json:"module"`
	ModuleSHA256 string   `json:"module_sha256"`
	License      string   `json:"license"`
	Signer       string   `json:"signer,omitempty"`
	Signature    string   `json:"signature,omitempty"`
}

// SigningPayload is the exact byte sequence signed by a trusted key. Core and
// SDK must agree on this order; any change requires a new ABI version.
func (m *Manifest) SigningPayload() []byte {
	if m == nil {
		return nil
	}
	return []byte(strings.Join([]string{
		m.ID,
		m.Version,
		m.ABI,
		m.MinMillivolt,
		m.Module,
		m.ModuleSHA256,
		strings.Join(m.Capabilities, ","),
		m.License,
	}, "\n"))
}

// Sign sets Signer and Signature from a private key.
func (m *Manifest) Sign(signer string, key ed25519.PrivateKey) error {
	if m == nil {
		return fmt.Errorf("nil manifest")
	}
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key must be %d bytes", ed25519.PrivateKeySize)
	}
	m.Signer = signer
	m.Signature = hex.EncodeToString(ed25519.Sign(key, m.SigningPayload()))
	return nil
}

// Load reads one bounded JSON manifest and refuses trailing content.
func Load(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("manifest %q: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("manifest %q: %w", path, err)
	}
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest %q: file exceeds the %d byte cap", path, MaxManifestBytes)
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("manifest %q: %w", path, err)
	}
	return m, nil
}

// Parse decodes a manifest from bytes under the same strict rules as Load.
func Parse(raw []byte) (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON content")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks every field at the install boundary. A manifest never gets
// a chance to be partially applied.
func (m *Manifest) Validate() error {
	if m == nil {
		return fmt.Errorf("nil manifest")
	}
	if !idPattern.MatchString(m.ID) {
		return fmt.Errorf("id: must be a lowercase identifier of at most 64 characters")
	}
	if !semverPattern.MatchString(m.Version) {
		return fmt.Errorf("version: must be a semantic version")
	}
	if m.ABI != v1.ABI {
		return fmt.Errorf("abi: must be %q, got %q", v1.ABI, m.ABI)
	}
	if !semverPattern.MatchString(m.MinMillivolt) {
		return fmt.Errorf("min_millivolt: must be a semantic version")
	}
	if len(m.Capabilities) == 0 || len(m.Capabilities) > MaxCapabilities {
		return fmt.Errorf("capabilities: must contain 1..%d entries", MaxCapabilities)
	}
	seen := map[string]bool{}
	for _, cap := range m.Capabilities {
		if seen[cap] {
			return fmt.Errorf("capabilities: duplicate %q", cap)
		}
		seen[cap] = true
		if !contains(Capabilities, cap) {
			return fmt.Errorf("capabilities: unknown %q", cap)
		}
	}
	if !modulePattern.MatchString(m.Module) || len(m.Module) > v1.MaxNameBytes {
		return fmt.Errorf("module: must be a .wasm filename")
	}
	decoded, err := hex.DecodeString(m.ModuleSHA256)
	if err != nil || len(decoded) != 32 || strings.ToLower(m.ModuleSHA256) != m.ModuleSHA256 {
		return fmt.Errorf("module_sha256: must be 64 lowercase hex characters")
	}
	if strings.TrimSpace(m.License) == "" || len(m.License) > v1.MaxNameBytes {
		return fmt.Errorf("license: must be a non-empty identifier of at most %d characters", v1.MaxNameBytes)
	}
	if (m.Signer == "") != (m.Signature == "") {
		return fmt.Errorf("signer and signature must be set together")
	}
	if m.Signer != "" {
		if !idPattern.MatchString(m.Signer) {
			return fmt.Errorf("signer: must be a lowercase identifier")
		}
		sig, err := hex.DecodeString(m.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize || strings.ToLower(m.Signature) != m.Signature {
			return fmt.Errorf("signature: must be %d lowercase hex characters", ed25519.SignatureSize*2)
		}
	}
	return nil
}

// Has reports whether the manifest requests a capability.
func (m *Manifest) Has(capability string) bool {
	if m == nil {
		return false
	}
	return contains(m.Capabilities, capability)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
