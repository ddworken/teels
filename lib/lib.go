package lib

// FakeAttestation represents a simulated attestation report
type FakeAttestation struct {
	AttestedData []byte `json:"attested_data"`
}
