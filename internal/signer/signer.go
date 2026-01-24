// internal/signer/signer.go
package signer

import (
    "crypto/ed25519"
    "fmt"
    "os"
)

// LoadPrivateKey reads the project-specific OpenSSH key and converts it to ed25519.PrivateKey
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
    keyData, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read key: %w", err)
    }
    
    // Note: SSH private keys often have wrappers (PEM). 
    // You may need to parse the block if not using a raw seed.
    // For simplicity, we assume a raw 32-byte seed for the daemon's internal use.
    if len(keyData) != ed25519.SeedSize {
         return nil, fmt.Errorf("invalid key size: expected 32 bytes")
    }

    return ed25519.NewKeyFromSeed(keyData), nil
}

// SignCommitment generates a 64-byte signature for a document state hash
func SignCommitment(privKey ed25519.PrivateKey, stateHash []byte) []byte {
    // Ed25519.Sign handles the internal hashing of the message (the hash) 
    // to prevent length extension attacks.
    return ed25519.Sign(privKey, stateHash)
}
