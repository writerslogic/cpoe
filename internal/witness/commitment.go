// Package witness provides cryptographic commitment primitives for binding
// file content, metadata, and edit topology into MMR leaves.
package witness

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

// MMRLeafPrefix is the domain separator for witness leaves.
const MMRLeafPrefix byte = 0x00

// ZeroHash is the canonical zero hash used for empty regions.
var ZeroHash = [32]byte{}

// Error types for commitment verification.
var (
	ErrMetadataMismatch = errors.New("metadata hash does not match commitment")
	ErrRegionsMismatch  = errors.New("regions root does not match commitment")
	ErrLeafMismatch     = errors.New("leaf hash does not match MMR")
)

// EditRegion represents a contiguous region of a file that was modified.
// StartPct and EndPct are normalized positions (0.0 to 1.0) within the file.
type EditRegion struct {
	StartPct  float32 // Start position as percentage (0.0-1.0)
	EndPct    float32 // End position as percentage (0.0-1.0)
	DeltaSign byte    // Sign of size change: 0=unchanged, 1=increase, 2=decrease
	ByteCount int32   // Number of bytes affected in this region
}

// ComputeMetadataHash produces deterministic hash of event metadata.
// This binds the SQLite event data to the MMR cryptographically.
//
// Canonical encoding order:
// 1. TimestampNs (int64, big-endian)
// 2. FileSize (int64, big-endian)
// 3. SizeDelta (int32, big-endian)
// 4. FilePath (UTF-8 string bytes, no length prefix - use remaining bytes)
func ComputeMetadataHash(timestampNs int64, fileSize int64, sizeDelta int32, filePath string) [32]byte {
	buf := new(bytes.Buffer)

	// Write TimestampNs (int64, big-endian)
	binary.Write(buf, binary.BigEndian, timestampNs)

	// Write FileSize (int64, big-endian)
	binary.Write(buf, binary.BigEndian, fileSize)

	// Write SizeDelta (int32, big-endian)
	binary.Write(buf, binary.BigEndian, sizeDelta)

	// Write FilePath (UTF-8 string bytes, no length prefix)
	buf.WriteString(filePath)

	return sha256.Sum256(buf.Bytes())
}

// hashRegion computes the hash of a single edit region.
// Format:
// [4 bytes: StartPct as float32 bits]
// [4 bytes: EndPct as float32 bits]
// [1 byte: DeltaSign]
// [4 bytes: ByteCount as int32]
func hashRegion(region EditRegion) [32]byte {
	buf := make([]byte, 13) // 4 + 4 + 1 + 4 = 13 bytes

	// StartPct as float32 bits (big-endian)
	binary.BigEndian.PutUint32(buf[0:4], math.Float32bits(region.StartPct))

	// EndPct as float32 bits (big-endian)
	binary.BigEndian.PutUint32(buf[4:8], math.Float32bits(region.EndPct))

	// DeltaSign
	buf[8] = region.DeltaSign

	// ByteCount as int32 (big-endian)
	binary.BigEndian.PutUint32(buf[9:13], uint32(region.ByteCount))

	return sha256.Sum256(buf)
}

// ComputeRegionsRoot builds Merkle root of edit regions.
// Returns zero hash if no regions (allows proofs without topology data).
//
// Each region is hashed as:
// [4 bytes: StartPct as float32 bits]
// [4 bytes: EndPct as float32 bits]
// [1 byte: DeltaSign]
// [4 bytes: ByteCount as int32]
//
// Tree is built bottom-up, padding with zero hash if odd number of nodes.
func ComputeRegionsRoot(regions []EditRegion) [32]byte {
	// No regions: return zero hash
	if len(regions) == 0 {
		return ZeroHash
	}

	// Single region: return hash of that region
	if len(regions) == 1 {
		return hashRegion(regions[0])
	}

	// Build bottom level: hash each region
	level := make([][32]byte, len(regions))
	for i, region := range regions {
		level[i] = hashRegion(region)
	}

	// Build tree bottom-up
	for len(level) > 1 {
		nextLevel := make([][32]byte, (len(level)+1)/2)

		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				// Hash pair
				nextLevel[i/2] = hashPair(level[i], level[i+1])
			} else {
				// Odd number of nodes: pad with zero hash
				nextLevel[i/2] = hashPair(level[i], ZeroHash)
			}
		}

		level = nextLevel
	}

	return level[0]
}

// hashPair computes the hash of two concatenated hashes.
func hashPair(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write(left[:])
	h.Write(right[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// ComputeMMRLeaf produces the value stored in the MMR.
// This is the cryptographic binding of content + metadata + topology.
//
// Format: SHA256(LeafPrefix || ContentHash || MetadataHash || RegionsRoot)
func ComputeMMRLeaf(contentHash, metadataHash, regionsRoot [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{MMRLeafPrefix})
	h.Write(contentHash[:])
	h.Write(metadataHash[:])
	h.Write(regionsRoot[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// VerifyMetadataBinding checks that event metadata matches the committed hash.
// Used during integrity verification to detect SQLite tampering.
func VerifyMetadataBinding(
	timestampNs int64,
	fileSize int64,
	sizeDelta int32,
	filePath string,
	regions []EditRegion,
	contentHash [32]byte,
	expectedLeafHash [32]byte,
) error {
	// Compute the components
	metadataHash := ComputeMetadataHash(timestampNs, fileSize, sizeDelta, filePath)
	regionsRoot := ComputeRegionsRoot(regions)
	leafHash := ComputeMMRLeaf(contentHash, metadataHash, regionsRoot)

	// Check leaf hash matches
	if leafHash != expectedLeafHash {
		return ErrLeafMismatch
	}

	return nil
}

// LeafComponents separates a leaf hash verification into its parts.
// Useful for debugging and audit trails.
type LeafComponents struct {
	ContentHash  [32]byte
	MetadataHash [32]byte
	RegionsRoot  [32]byte
	LeafHash     [32]byte
}

// ComputeLeafComponents computes all components of an MMR leaf.
func ComputeLeafComponents(
	contentHash [32]byte,
	timestampNs int64,
	fileSize int64,
	sizeDelta int32,
	filePath string,
	regions []EditRegion,
) *LeafComponents {
	metadataHash := ComputeMetadataHash(timestampNs, fileSize, sizeDelta, filePath)
	regionsRoot := ComputeRegionsRoot(regions)
	leafHash := ComputeMMRLeaf(contentHash, metadataHash, regionsRoot)

	return &LeafComponents{
		ContentHash:  contentHash,
		MetadataHash: metadataHash,
		RegionsRoot:  regionsRoot,
		LeafHash:     leafHash,
	}
}

// TestLeafRoundTrip verifies commitment computation is deterministic.
// Returns error if recomputation produces different hash.
func TestLeafRoundTrip(lc *LeafComponents, regions []EditRegion, filePath string, timestampNs int64, fileSize int64, sizeDelta int32) error {
	// Recompute metadata hash
	metadataHash := ComputeMetadataHash(timestampNs, fileSize, sizeDelta, filePath)
	if metadataHash != lc.MetadataHash {
		return ErrMetadataMismatch
	}

	// Recompute regions root
	regionsRoot := ComputeRegionsRoot(regions)
	if regionsRoot != lc.RegionsRoot {
		return ErrRegionsMismatch
	}

	// Recompute leaf hash
	leafHash := ComputeMMRLeaf(lc.ContentHash, metadataHash, regionsRoot)
	if leafHash != lc.LeafHash {
		return ErrLeafMismatch
	}

	return nil
}
