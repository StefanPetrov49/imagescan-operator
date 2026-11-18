package controller

import (
	"crypto/sha256"
	"encoding/hex"

	"k8s.io/apimachinery/pkg/types"
)

// scanID returns a stable ID for one image within one ImageScan.
// Same inputs always give the same ID, which keeps reconcile idempotent.
func scanID(scanUID types.UID, image string) string {
	sum := sha256.Sum256([]byte(string(scanUID) + "/" + image))
	return hex.EncodeToString(sum[:])[:16]
}
