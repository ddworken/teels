package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ddworken/teels/lib"
	nitro "github.com/veracruz-project/go-nitro-enclave-attestation-document"
)

func getAttestationBytes(encodedSubdomainPart string) ([]byte, error) {
	filePath := filepath.Join("output-attestations", encodedSubdomainPart+".bin")

	// Read the attestation file
	attestationBytes, err := os.ReadFile(filePath)
	if err == nil {
		return attestationBytes, nil
	}

	// If the file doesn't exist, fetch it from the server
	hostname := os.Getenv("VERIFIED_HOST_NAME")
	if hostname == "" {
		return nil, fmt.Errorf("VERIFIED_HOST_NAME environment variable is not set")
	}

	url := fmt.Sprintf("http://%s/static/output-attestations/%s.bin", hostname, encodedSubdomainPart)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attestation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch attestation: status code %d", resp.StatusCode)
	}

	attestationBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation response: %w", err)
	}

	return attestationBytes, nil

}

func validateAttestationForPublicKeyHash(decodedSubdomainPart []byte, pubKeyHash []byte) error {
	encodedSubdomainPart := lib.Base32Encoder.EncodeToString(decodedSubdomainPart)
	attestationBytes, err := getAttestationBytes(encodedSubdomainPart)
	if err != nil {
		return fmt.Errorf("error getting attestation bytes: %v", err)
	}

	// Deserialize the attestation
	var attestation lib.AttestationReport
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		return fmt.Errorf("error deserializing attestation: %v", err)
	}

	// Check if the attested data matches the pubKeyHash
	if !bytes.Equal(attestation.UnverifiedAttestedData, pubKeyHash) {
		return fmt.Errorf("attested data does not match public key hash: pubKeyHash: %x attestedData: %x", pubKeyHash, attestation.UnverifiedAttestedData)
	}

	return nil
}

func validateAwsNitroAttestation(pubKeyHash []byte, attestation lib.AttestationReport) error {
	if attestation.AwsNitroAttestation == nil {
		return fmt.Errorf("no AWS Nitro attestation data found")
	}

	// Read the AWS Nitro root certificate
	rootCertPEM, err := os.ReadFile("cert_verifier/aws_nitro_root.pem")
	if err != nil {
		return fmt.Errorf("failed to read AWS Nitro root certificate: %w", err)
	}

	block, _ := pem.Decode(rootCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("failed to decode PEM block containing certificate")
	}

	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root certificate: %w", err)
	}

	// Validate the attestation document using the veracruz-project library
	doc, err := nitro.AuthenticateDocument(attestation.AwsNitroAttestation, *rootCert, true)
	if err != nil {
		return fmt.Errorf("failed to validate AWS Nitro attestation: %w", err)
	}

	if !bytes.Equal(doc.User_Data, pubKeyHash) {
		return fmt.Errorf("attested data does not match public key hash: pubKeyHash: %x attestedData: %x", pubKeyHash, doc.User_Data)
	}

	return nil
}

// validateCertificate takes an x509 certificate and performs a series of validations.
// It returns an error if any validation fails, otherwise nil.
func validateCertificate(cert *x509.Certificate) error {
	log.Println("Starting certificate validation...")

	// Get the expected host name from environment variable
	expectedBaseDomain := os.Getenv("VERIFIED_HOST_NAME")
	if expectedBaseDomain == "" {
		return fmt.Errorf("VERIFIED_HOST_NAME environment variable is not set")
	}

	// 1. Check Hostnames
	log.Println("Step 1: Validating hostnames...")
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
	log.Printf(" -> Hostnames validated: %s, %s\n", expectedBaseDomain, subdomainHostname)

	// 2. Parse Subdomain and Decode Base32
	log.Println("Step 2: Parsing and decoding subdomain...")
	subdomainPart := strings.TrimSuffix(subdomainHostname, "."+expectedBaseDomain)
	if subdomainPart == "" {
		return fmt.Errorf("extracted subdomain part is empty for hostname %s", subdomainHostname)
	}

	// Use standard Base32 decoding without padding
	decodedSubdomainPart, err := lib.Base32Encoder.DecodeString(strings.ToUpper(subdomainPart))
	if err != nil {
		return fmt.Errorf("failed to decode subdomain '%s' using Base32: %w", subdomainPart, err)
	}
	log.Printf(" -> Decoded subdomain '%s' to: %x\n", subdomainPart, decodedSubdomainPart)

	// 3. Calculate Public Key SHA256 Hash and Compare with REPORT_DATA
	log.Println("Step 3: Calculating public key hash and comparing with REPORT_DATA...")
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyHash := sha256.Sum256(pubKeyBytes)
	log.Printf(" -> Calculated public key SHA256 hash: %x\n", pubKeyHash)

	// 4. Validate the attestation
	log.Println("Step 4: Fetching attestation...")
	err = validateAttestationForPublicKeyHash(decodedSubdomainPart, pubKeyHash[:])
	if err != nil {
		return fmt.Errorf("failed to validate attestation for public key hash: %w", err)
	}

	log.Println(" -> Public key hash matches REPORT_DATA.")
	log.Println("Certificate validation successful!")
	return nil
}

func verifyFromFile() {
	certPEM, err := os.ReadFile("output-keys/certificate.crt")
	if err != nil {
		log.Printf("Error reading certificate file: %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Println("Error: Failed to decode PEM block containing certificate")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Error parsing certificate: %v\n", err)
		return
	}

	// Run the validation
	err = validateCertificate(cert)
	if err != nil {
		log.Printf("\n--- Certificate Validation FAILED ---\nError: %v\n", err)
		os.Exit(1)
	} else {
		log.Println("\n--- Certificate Validation SUCCEEDED ---")
	}
}

func main() {
	// Get the hostname from environment variable
	hostname := os.Getenv("VERIFIED_HOST_NAME")
	if hostname == "" {
		log.Fatal("VERIFIED_HOST_NAME environment variable is not set")
	}

	// Set up TLS configuration
	config := &tls.Config{
		InsecureSkipVerify: true, // We'll verify the certificate ourselves
	}

	// Connect to the server
	conn, err := tls.Dial("tcp", hostname+":443", config)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Get the certificate chain
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Fatal("No certificates received from server")
	}

	// Get the leaf certificate (first in the chain)
	cert := state.PeerCertificates[0]

	// Run the validation
	err = validateCertificate(cert)
	if err != nil {
		log.Printf("\n--- Certificate Validation FAILED ---\nError: %v\n", err)
		os.Exit(1)
	} else {
		log.Println("\n--- Certificate Validation SUCCEEDED ---")
	}
}
