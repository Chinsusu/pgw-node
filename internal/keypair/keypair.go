// internal/keypair/keypair.go — Ed25519 keypair management for pgw-node.
// Uses a simple binary format: raw 64-byte ed25519 private key, hex-encoded.
package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyPair holds an Ed25519 key pair.
type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Generate creates a new Ed25519 keypair and saves it to keyPath.
// Format: hex-encoded private key (64 bytes = 128 hex chars), one line.
// Public key is saved to keyPath + ".pub" as hex.
func Generate(keyPath string) (*KeyPair, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	privHex := hex.EncodeToString([]byte(priv))
	if err := os.WriteFile(keyPath, []byte(privHex+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write private key: %w", err)
	}

	pubHex := hex.EncodeToString(pub)
	if err := os.WriteFile(keyPath+".pub", []byte(pubHex+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("write public key: %w", err)
	}

	return &KeyPair{Private: priv, Public: pub}, nil
}

// Load reads an existing keypair from keyPath (hex-encoded private key).
func Load(keyPath string) (*KeyPair, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", keyPath, err)
	}

	privHex := strings.TrimSpace(string(raw))
	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key in %s (expected %d bytes hex, got %d bytes)", keyPath, ed25519.PrivateKeySize, len(privBytes))
	}

	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{Private: priv, Public: pub}, nil
}

// PublicKeyHex returns the public key as a hex string.
func (kp *KeyPair) PublicKeyHex() string {
	return hex.EncodeToString(kp.Public)
}

// Sign signs a message using the private key, returns hex-encoded signature.
func (kp *KeyPair) Sign(message []byte) string {
	sig := ed25519.Sign(kp.Private, message)
	return hex.EncodeToString(sig)
}
