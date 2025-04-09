package lib

import (
	"encoding/base32"
)

// Base32Encoder is the standard base32 encoder with no padding, used for encoding/decoding attestation data
var Base32Encoder = base32.StdEncoding.WithPadding(base32.NoPadding)

// FakeAttestation represents a simulated attestation report
type FakeAttestation struct {
	AttestedData []byte `json:"attested_data"`
}
