package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ddworken/teels/lib"

	nitro "github.com/veracruz-project/go-nitro-enclave-attestation-document"
)

// EifInfo represents the structure of the eif-info.txt file
type EifInfo struct {
	EifVersion   int `json:"EifVersion"`
	Measurements struct {
		HashAlgorithm string `json:"HashAlgorithm"`
		PCR0          string `json:"PCR0"`
		PCR1          string `json:"PCR1"`
		PCR2          string `json:"PCR2"`
	} `json:"Measurements"`
}

// PcrValues represents the PCR values for a specific version
type PcrValues struct {
	Version string
	PCR0    string
	PCR1    string
	PCR2    string
}

// GitHubRelease represents a release from the GitHub API
type GitHubRelease struct {
	TagName string `json:"tag_name"`
}

// retrieveExpectedPcrs downloads and processes eif-info.txt files from all available releases
// TODO: This currently just trusts the PCR values listed on GH releases. Ideally, we would actually
// validate the sigstore signatures on top of those files.
func retrieveExpectedPcrs() ([]PcrValues, error) {
	var results []PcrValues

	// Fetch list of releases from GitHub API
	releasesUrl := "https://api.github.com/repos/ddworken/teels/releases"
	resp, err := httpGetWithRetryAndCaching(releasesUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch releases: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status code %d", resp.StatusCode)
	}

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("failed to decode releases JSON: %v", err)
	}

	for _, release := range releases {
		// Skip releases that don't match our version pattern
		if !strings.HasPrefix(release.TagName, "v0.") {
			continue
		}

		url := fmt.Sprintf("https://github.com/ddworken/teels/releases/download/%s/eif-info.txt", release.TagName)
		resp, err := httpGetWithRetryAndCaching(url)
		if err != nil {
			log.Printf("Warning: Failed to fetch %s: %v", release.TagName, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode != http.StatusNotFound {
				log.Printf("Warning: %s returned status code %d", release.TagName, resp.StatusCode)
			}
			resp.Body.Close()
			continue
		}

		var eifInfo EifInfo
		decoder := json.NewDecoder(resp.Body)
		if err := decoder.Decode(&eifInfo); err != nil {
			log.Printf("Warning: Failed to decode JSON for %s: %v", release.TagName, err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		results = append(results, PcrValues{
			Version: release.TagName,
			PCR0:    eifInfo.Measurements.PCR0,
			PCR1:    eifInfo.Measurements.PCR1,
			PCR2:    eifInfo.Measurements.PCR2,
		})
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no valid PCR values found from any version")
	}

	return results, nil
}

// httpGetWithRetryAndCaching performs an HTTP GET request with retry logic for 429 responses and caches successful responses
func httpGetWithRetryAndCaching(url string) (*http.Response, error) {
	// Create cache directory if it doesn't exist
	cacheDir := "/tmp/http-get-cache"
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Create a cache key from the URL
	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(url)))
	cachePath := filepath.Join(cacheDir, cacheKey)

	// Try to read from cache first
	if cachedData, err := os.ReadFile(cachePath); err == nil {
		// Create a response from cached data
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(cachedData)),
		}, nil
	}

	maxRetries := 5
	baseDelay := 1 * time.Second
	maxDelay := 20 * time.Second

	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			// Read the response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				resp.Body.Close()
				return nil, fmt.Errorf("failed to read response body: %w", err)
			}
			resp.Body.Close()

			// Cache the successful response
			if err := os.WriteFile(cachePath, body, 0644); err != nil {
				log.Printf("Warning: failed to cache response: %v", err)
			}

			// Return a new response with the cached body
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			resp.Body.Close()
			return resp, nil
		}

		// Calculate exponential backoff with jitter
		// 2^i gives us exponential growth (1, 2, 4 seconds)
		// rand.Float64() * 0.5 gives us up to 50% jitter
		delay := baseDelay * time.Duration(1<<i)
		jitter := time.Duration(rand.Float64() * 0.5 * float64(delay))
		waitTime := delay + jitter

		// Cap the maximum wait time
		if waitTime > maxDelay {
			waitTime = maxDelay
		}

		log.Printf("Received 429 response, waiting %v before retry %d/%d", waitTime, i+1, maxRetries)
		time.Sleep(waitTime)
		resp.Body.Close()
	}

	return nil, fmt.Errorf("max retries (%d) exceeded for URL: %s", maxRetries, url)
}

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
	resp, err := httpGetWithRetryAndCaching(url)
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

	return validateAwsNitroAttestation(string(attestation.AwsNitroAttestation), attestation.UnverifiedAttestedData)
}

func validateAwsNitroAttestation(base64EncodedAttestation string, expectedAttestedData []byte) error {
	if base64EncodedAttestation == "" {
		return fmt.Errorf("no AWS Nitro attestation data found")
	}

	attestationBytes, err := base64.StdEncoding.DecodeString(base64EncodedAttestation)
	if err != nil {
		return fmt.Errorf("failed to decode AWS Nitro attestation: %w", err)
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

	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		return fmt.Errorf("failed to verify root certificate signature: %w", err)
	}

	// Validate the attestation document using the veracruz-project library
	doc, err := nitro.AuthenticateDocument(attestationBytes, *rootCert, true)
	if err != nil {
		return fmt.Errorf("failed to validate AWS Nitro attestation: %w", err)
	}

	// Base32 decode the user data field
	base32DecodedUserData, err := lib.Base32Encoder.DecodeString(string(doc.User_Data))
	if err != nil {
		return fmt.Errorf("failed to base32 decode user data: %w", err)
	}

	if !bytes.Equal(expectedAttestedData, base32DecodedUserData) {
		return fmt.Errorf("attested data does not match expected attested data: expected: %x actual: %x", expectedAttestedData, base32DecodedUserData)
	}

	// Retrieve expected PCR values from all versions
	expectedPcrs, err := retrieveExpectedPcrs()
	if err != nil {
		return fmt.Errorf("failed to retrieve expected PCR values: %w", err)
	}

	// Convert PCR values to hex strings for comparison
	pcrHexValues := make([]string, 3)
	for i := int32(0); i < 3; i++ {
		pcrHexValues[i] = fmt.Sprintf("%x", doc.PCRs[i])
	}

	// Find matching version by comparing PCR values
	var matchingVersion string
	for _, pcrSet := range expectedPcrs {
		if pcrHexValues[0] == pcrSet.PCR0 &&
			pcrHexValues[1] == pcrSet.PCR1 &&
			pcrHexValues[2] == pcrSet.PCR2 {
			matchingVersion = pcrSet.Version
			log.Printf("Attestation matches version tag: %s", matchingVersion)
			break
		}
	}

	if matchingVersion == "" {
		return fmt.Errorf("PCR values do not match any known version: PCR0=%s PCR1=%s PCR2=%s",
			pcrHexValues[0], pcrHexValues[1], pcrHexValues[2])
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

// queryCTLogs queries the crt.sh API for certificates matching the given domain
func queryCTLogs(domain string) ([]*x509.Certificate, error) {
	// Construct the crt.sh API URL for initial search
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)

	// Make the HTTP request
	resp, err := httpGetWithRetryAndCaching(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh API returned status code %d", resp.StatusCode)
	}

	// Parse the JSON response
	var certs []struct {
		ID                 int    `json:"id"`
		LoggedAt           string `json:"entry_timestamp"`
		NotBefore          string `json:"not_before"`
		NotAfter           string `json:"not_after"`
		CommonName         string `json:"common_name"`
		MatchingIdentities string `json:"matching_identities"`
		SerialNumber       string `json:"serial_number"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, fmt.Errorf("failed to decode crt.sh response: %w", err)
	}

	log.Printf("Found %d certificates in CT logs", len(certs))

	// Convert certificates to x509.Certificate objects
	var x509Certs []*x509.Certificate
	now := time.Now()

	for _, cert := range certs {
		// Skip certificates that are already expired
		notAfter, err := time.Parse("2006-01-02T15:04:05", cert.NotAfter)
		if err != nil {
			log.Printf("Warning: failed to parse NotAfter date for certificate %d: %v", cert.ID, err)
			continue
		}
		if notAfter.Before(now) {
			log.Printf("Skipping expired certificate %d (expired on %s)", cert.ID, notAfter.Format(time.RFC3339))
			continue
		}

		// Fetch the actual certificate using the ID
		certURL := fmt.Sprintf("https://crt.sh/?d=%d", cert.ID)
		certResp, err := httpGetWithRetryAndCaching(certURL)
		if err != nil {
			log.Printf("Warning: failed to fetch certificate %d: %v", cert.ID, err)
			continue
		}
		defer certResp.Body.Close()

		if certResp.StatusCode != http.StatusOK {
			log.Printf("Warning: failed to fetch certificate %d: status code %d", cert.ID, certResp.StatusCode)
			continue
		}

		// Read the certificate data
		certBytes, err := io.ReadAll(certResp.Body)
		if err != nil {
			log.Printf("Warning: failed to read certificate %d: %v", cert.ID, err)
			continue
		}

		// Try to parse as PEM first
		block, _ := pem.Decode(certBytes)
		if block != nil && block.Type == "CERTIFICATE" {
			certBytes = block.Bytes
		}

		// Parse the certificate
		x509Cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Printf("Warning: failed to parse certificate %d: %v (certificate bytes length: %d)",
				cert.ID, err, len(certBytes))
			continue
		}

		// Double check the expiration time from the parsed certificate
		if x509Cert.NotAfter.Before(now) {
			log.Printf("Skipping expired certificate %d (expired on %s)", cert.ID, x509Cert.NotAfter.Format(time.RFC3339))
			continue
		}

		x509Certs = append(x509Certs, x509Cert)
	}

	if len(x509Certs) == 0 {
		return nil, fmt.Errorf("no valid unexpired certificates found in CT logs")
	}

	return x509Certs, nil
}

func verifyFromHttpsRequest(hostname string) {
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

func main() {
	hostname := os.Getenv("VERIFIED_HOST_NAME")
	if hostname == "" {
		log.Fatal("VERIFIED_HOST_NAME environment variable is not set")
	}

	verifyFromHttpsRequest(hostname)

	// Query CT logs for the hostname
	// log.Printf("Querying CT logs for %s...", hostname)
	// ctCerts, err := queryCTLogs(hostname)
	// if err != nil {
	// 	log.Fatalf("Warning: failed to query CT logs: %v", err)
	// }
	// log.Printf("Found %d certificates in CT logs", len(ctCerts))
	// for i, cert := range ctCerts {
	// 	log.Printf("Certificate %d: %s (valid from %s to %s)",
	// 		i+1, cert.Subject.CommonName,
	// 		cert.NotBefore.Format(time.RFC3339),
	// 		cert.NotAfter.Format(time.RFC3339))

	// 	err = validateCertificate(cert)
	// 	if err != nil {
	// 		log.Printf("Certificate %d validation failed: %v", i+1, err)
	// 	} else {
	// 		log.Printf("Certificate %d validation succeeded", i+1)
	// 	}
	// }
}
