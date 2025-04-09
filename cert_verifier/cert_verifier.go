package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil" // Or os.ReadFile in Go 1.16+
	"os"
	"path/filepath"
	"strings"
)

// FakeAttestation represents a simplified attestation structure
type FakeAttestation struct {
	AttestedData []byte `json:"attested_data"`
}

const (
	reportDataLength = 64 // Standard length for SEV/SNP REPORT_DATA
	hashLength       = 32 // SHA256 hash length
)

func validateAttestationForPublicKeyHash(decodedSubdomainPart []byte, pubKeyHash []byte) error {
	encodedSubdomainPart := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decodedSubdomainPart)
	filePath := filepath.Join("output-attestations", encodedSubdomainPart+".bin")

	// Read the attestation file
	attestationBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("Error reading attestation file: %v\n", err)
	}

	// Deserialize the attestation
	var attestation FakeAttestation
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		return fmt.Errorf("Error deserializing attestation: %v\n", err)
	}

	// Check if the attested data matches the pubKeyHash
	if !bytes.Equal(attestation.AttestedData, pubKeyHash) {
		return fmt.Errorf("Attested data does not match public key hash: \npubKeyHash:   %x \nattestedData: %x", pubKeyHash, attestation.AttestedData)
	}

	return nil
}

// validateCertificate takes an x509 certificate and performs a series of validations.
// It returns an error if any validation fails, otherwise nil.
func validateCertificate(cert *x509.Certificate) error {
	fmt.Println("Starting certificate validation...")

	// Get the expected host name from environment variable
	expectedBaseDomain := os.Getenv("VERIFIED_HOST_NAME")
	if expectedBaseDomain == "" {
		return fmt.Errorf("VERIFIED_HOST_NAME environment variable is not set")
	}

	// 1. Check Hostnames
	fmt.Println("Step 1: Validating hostnames...")
	if len(cert.DNSNames) != 2 {
		return fmt.Errorf("expected exactly 2 DNS names, but found %d", len(cert.DNSNames))
	}

	var foundBaseDomain bool
	var subdomainHostname string
	for _, name := range cert.DNSNames {
		if name == expectedBaseDomain {
			foundBaseDomain = true
		} else if strings.HasSuffix(name, "."+expectedBaseDomain) {
			if subdomainHostname != "" {
				return fmt.Errorf("found more than one subdomain of %s: %s and %s", expectedBaseDomain, subdomainHostname, name)
			}
			subdomainHostname = name
		} else {
			return fmt.Errorf("unexpected hostname found: %s", name)
		}
	}

	if !foundBaseDomain {
		return fmt.Errorf("required base domain %s not found in DNS names", expectedBaseDomain)
	}
	if subdomainHostname == "" {
		return fmt.Errorf("required subdomain of %s not found in DNS names", expectedBaseDomain)
	}
	fmt.Printf(" -> Hostnames validated: %s, %s\n", expectedBaseDomain, subdomainHostname)

	// 2. Parse Subdomain and Decode Base32
	fmt.Println("Step 2: Parsing and decoding subdomain...")
	subdomainPart := strings.TrimSuffix(subdomainHostname, "."+expectedBaseDomain)
	if subdomainPart == "" {
		return fmt.Errorf("extracted subdomain part is empty for hostname %s", subdomainHostname)
	}

	// Use standard Base32 decoding without padding
	decodedSubdomainPart, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(subdomainPart))
	if err != nil {
		return fmt.Errorf("failed to decode subdomain '%s' using Base32: %w", subdomainPart, err)
	}
	fmt.Printf(" -> Decoded subdomain '%s' to: %x\n", subdomainPart, decodedSubdomainPart)

	// 3. Calculate Public Key SHA256 Hash and Compare with REPORT_DATA
	fmt.Println("Step 3: Calculating public key hash and comparing with REPORT_DATA...")
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyHash := sha256.Sum256(pubKeyBytes)
	fmt.Printf(" -> Calculated public key SHA256 hash: %x\n", pubKeyHash)

	// 4. Validate the attestation
	fmt.Println("Step 4: Fetching attestation...")
	err = validateAttestationForPublicKeyHash(decodedSubdomainPart, pubKeyHash[:])
	if err != nil {
		return fmt.Errorf("failed to validate attestation for public key hash: %w", err)
	}
	/*
		// 4. Parse and Verify Attestation using go-sev-guest
		fmt.Println("Step 4: Parsing and verifying attestation report...")
		// You might need to provide VerifyOpts, e.g., if you need to check against
		// specific root CAs (ASK/ARK). For basic parsing and REPORT_DATA extraction,
		// default options might suffice, but proper verification often requires more context.
		// Consult go-sev-guest documentation for details on verification options.
		opts := &sev_guest.VerifyOpts{} // Placeholder for verification options
		parsedAttestation, err := sev_guest.VerifyAttestation(attestationBytes, opts)
		if err != nil {
			return fmt.Errorf("failed to parse or verify attestation report: %w", err)
		}
		// Note: VerifyAttestation performs parsing and potentially cryptographic verification
		// depending on the options provided. Ensure 'opts' is configured correctly
		// for your security requirements.
		fmt.Println(" -> Attestation parsed and verified successfully.")

		// 5. Extract REPORT_DATA
		fmt.Println("Step 5: Extracting REPORT_DATA...")
		// Assuming the parsedAttestation struct has a field like ReportData or similar.
		// Adjust the field access based on the actual structure returned by go-sev-guest.
		// For SNP, this is typically within an AttestationReport struct.
		// We'll assume a structure like `parsedAttestation.Report.ReportData` for demonstration.
		// PLEASE VERIFY the correct field path in the go-sev-guest library's types.
		// Let's assume VerifyAttestation returns a struct containing the report,
		// and the report has a `ReportData` field.
		// Example structure assumption:
		// type SnpReport struct { ReportData [64]byte; ... }
		// type Attestation struct { Report SnpReport; ... }
		// reportData := parsedAttestation.Report.ReportData // Adjust based on actual struct

		// --- Direct access depends heavily on go-sev-guest version & attestation type (SEV/ES/SNP) ---
		// --- You MUST inspect the `parsedAttestation` structure provided by the library ---
		// --- For demonstration, let's assume it has a method or field `GetReportData()` ---
		// --- which returns a []byte slice of length 64. ---

		// Placeholder: Replace with actual access to REPORT_DATA from parsedAttestation
		var reportData []byte
		// Example using a hypothetical GetReportData method:
		// reportData = parsedAttestation.GetReportData()
		// Or direct field access if available (adjust path):
		// reportData = parsedAttestation.Report.ReportData[:] // Assuming [64]byte array

		// *** You MUST replace this placeholder section ***
		// Example: Accessing ReportData for SNP (check go-sev-guest docs for exact structure)
		if report, ok := parsedAttestation.Report.(*sev_guest.SnpReport); ok {
			reportData = report.ReportData[:] // Access the 64-byte array as a slice
		} else {
			return fmt.Errorf("could not access SNP report data from parsed attestation (type assertion failed or structure unexpected)")
		}
		// *** End of placeholder section ***

		if len(reportData) != reportDataLength {
			return fmt.Errorf("extracted REPORT_DATA has unexpected length: expected %d, got %d", reportDataLength, len(reportData))
		}
		fmt.Printf(" -> Extracted REPORT_DATA (%d bytes)\n", len(reportData))

	*/

	/*
		// 6. Calculate Public Key SHA256 Hash and Compare with REPORT_DATA
		fmt.Println("Step 6: Calculating public key hash and comparing with REPORT_DATA...")
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to marshal public key: %w", err)
		}
		pubKeyHash := sha256.Sum256(pubKeyBytes)
		fmt.Printf(" -> Calculated public key SHA256 hash: %x\n", pubKeyHash)

	*/
	/*
		// SEV/SNP attestation reports place the custom data (like the public key hash)
		// in the first 32 bytes of the 64-byte REPORT_DATA field.
		reportDataHash := reportData[:hashLength] // Extract the first 32 bytes

		if !bytes.Equal(pubKeyHash[:], reportDataHash) {
			return fmt.Errorf("public key hash (%x) does not match REPORT_DATA hash (%x)", pubKeyHash, reportDataHash)
		}
	*/

	fmt.Println(" -> Public key hash matches REPORT_DATA.")
	fmt.Println("Certificate validation successful!")
	return nil
}

// --- Example Usage ---

func main() {
	certPEM, err := ioutil.ReadFile("output-keys/certificate.crt")
	if err != nil {
		fmt.Printf("Error reading certificate file: %v\n", err)
		// Use os.Exit(1) for failure in main
		return // Or panic, depending on desired program behavior
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println("Error: Failed to decode PEM block containing certificate")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("Error parsing certificate: %v\n", err)
		return
	}

	// Run the validation
	err = validateCertificate(cert)
	if err != nil {
		// If any validation fails, the overall program should fail.
		// Log the specific error and exit, or panic.
		fmt.Printf("\n--- Certificate Validation FAILED ---\nError: %v\n", err)
		// os.Exit(1) // Use this in a real application to indicate failure
	} else {
		fmt.Println("\n--- Certificate Validation SUCCEEDED ---")
	}
}
