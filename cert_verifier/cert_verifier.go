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

// HTTPClient interface for mocking HTTP requests
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// FileSystem interface for mocking file operations
type FileSystem interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
}

// RealFileSystem implements FileSystem using actual file operations
type RealFileSystem struct{}

func (fs RealFileSystem) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (fs RealFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

func (fs RealFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

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

const (
	maxRetries    = 5
	baseDelay     = time.Second
	maxDelay      = 20 * time.Second
	cacheDir      = "/tmp/http-get-cache"
	githubBaseURL = "https://api.github.com/repos/ddworken/teels"
)

// retrieveExpectedPcrs downloads and processes eif-info.txt files from all available releases
// TODO: This currently just trusts the PCR values listed on GH releases. Ideally, we would actually
// validate the sigstore signatures on top of those files.
func retrieveExpectedPcrs(client HTTPClient, fs FileSystem) ([]PcrValues, error) {
	var results []PcrValues

	req, err := http.NewRequest("GET", githubBaseURL+"/releases", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status code %d", resp.StatusCode)
	}

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("failed to decode releases JSON: %w", err)
	}

	for _, release := range releases {
		if !strings.HasPrefix(release.TagName, "v0.") {
			continue
		}

		url := fmt.Sprintf("https://github.com/ddworken/teels/releases/download/%s/eif-info.txt", release.TagName)
		resp, err := httpGetWithRetryAndCaching(url, client, fs)
		if err != nil {
			log.Printf("Warning: Failed to fetch %s: %v", release.TagName, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode != http.StatusNotFound {
				log.Printf("Warning: %s returned status code %d", release.TagName, resp.StatusCode)
			}
			continue
		}

		var eifInfo EifInfo
		if err := json.NewDecoder(resp.Body).Decode(&eifInfo); err != nil {
			log.Printf("Warning: Failed to decode JSON for %s: %v", release.TagName, err)
			continue
		}

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

// httpGetWithRetryAndCaching performs an HTTP GET request with retry logic and caching
func httpGetWithRetryAndCaching(url string, client HTTPClient, fs FileSystem) (*http.Response, error) {
	if err := fs.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(url)))
	cachePath := filepath.Join(cacheDir, cacheKey)

	if cachedData, err := fs.ReadFile(cachePath); err == nil {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(cachedData)),
		}, nil
	}

	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				resp.Body.Close()
				return nil, fmt.Errorf("failed to read response body: %w", err)
			}
			resp.Body.Close()

			if err := fs.WriteFile(cachePath, body, 0644); err != nil {
				log.Printf("Warning: failed to cache response: %v", err)
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			resp.Body.Close()
			return resp, nil
		}

		delay := baseDelay * time.Duration(1<<i)
		jitter := time.Duration(rand.Float64() * 0.5 * float64(delay))
		waitTime := min(delay+jitter, maxDelay)

		log.Printf("Received 429 response, waiting %v before retry %d/%d", waitTime, i+1, maxRetries)
		time.Sleep(waitTime)
		resp.Body.Close()
	}

	return nil, fmt.Errorf("max retries (%d) exceeded for URL: %s", maxRetries, url)
}

func getAttestationBytes(encodedSubdomainPart string, client HTTPClient, fs FileSystem) ([]byte, error) {
	url := fmt.Sprintf("http://teels-attestations.s3.ap-south-1.amazonaws.com/%s.bin", encodedSubdomainPart)
	resp, err := httpGetWithRetryAndCaching(url, client, fs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attestation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return io.ReadAll(resp.Body)
	}
	return nil, fmt.Errorf("failed to fetch attestation from %s: status code %d", url, resp.StatusCode)
}

func validateAttestationForPublicKeyHash(decodedSubdomainPart []byte, pubKeyHash []byte, client HTTPClient, fs FileSystem) error {
	encodedSubdomainPart := lib.Base32Encoder.EncodeToString(decodedSubdomainPart)
	attestationBytes, err := getAttestationBytes(encodedSubdomainPart, client, fs)
	if err != nil {
		return fmt.Errorf("error getting attestation bytes: %w", err)
	}

	var attestation lib.AttestationReport
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		return fmt.Errorf("error deserializing attestation: %w", err)
	}

	if !bytes.Equal(attestation.UnverifiedAttestedData, pubKeyHash) {
		return fmt.Errorf("attested data does not match public key hash: pubKeyHash: %x attestedData: %x",
			pubKeyHash, attestation.UnverifiedAttestedData)
	}

	return validateAwsNitroAttestation(string(attestation.AwsNitroAttestation), attestation.UnverifiedAttestedData, client, fs)
}

func validateAwsNitroAttestation(base64EncodedAttestation string, expectedAttestedData []byte, client HTTPClient, fs FileSystem) error {
	if base64EncodedAttestation == "" {
		return fmt.Errorf("no AWS Nitro attestation data found")
	}

	attestationBytes, err := base64.StdEncoding.DecodeString(base64EncodedAttestation)
	if err != nil {
		return fmt.Errorf("failed to decode AWS Nitro attestation: %w", err)
	}

	rootCertPEM, err := fs.ReadFile("cert_verifier/aws_nitro_root.pem")
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

	doc, err := nitro.AuthenticateDocument(attestationBytes, *rootCert, true)
	if err != nil {
		return fmt.Errorf("failed to validate AWS Nitro attestation: %w", err)
	}

	base32DecodedUserData, err := lib.Base32Encoder.DecodeString(string(doc.User_Data))
	if err != nil {
		return fmt.Errorf("failed to base32 decode user data: %w", err)
	}

	if !bytes.Equal(expectedAttestedData, base32DecodedUserData) {
		return fmt.Errorf("attested data does not match expected attested data: expected: %x actual: %x",
			expectedAttestedData, base32DecodedUserData)
	}

	expectedPcrs, err := retrieveExpectedPcrs(client, fs)
	if err != nil {
		return fmt.Errorf("failed to retrieve expected PCR values: %w", err)
	}

	pcrHexValues := make([]string, 3)
	for i := int32(0); i < 3; i++ {
		pcrHexValues[i] = fmt.Sprintf("%x", doc.PCRs[i])
	}

	for _, pcrSet := range expectedPcrs {
		if pcrHexValues[0] == pcrSet.PCR0 &&
			pcrHexValues[1] == pcrSet.PCR1 &&
			pcrHexValues[2] == pcrSet.PCR2 {
			log.Printf("Attestation matches version tag: %s", pcrSet.Version)
			return nil
		}
	}

	return fmt.Errorf("PCR values do not match any known version: PCR0=%s PCR1=%s PCR2=%s",
		pcrHexValues[0], pcrHexValues[1], pcrHexValues[2])
}

// validateCertificate takes an x509 certificate and performs a series of validations.
// It returns an error if any validation fails, otherwise nil.
func validateCertificate(cert *x509.Certificate, client HTTPClient, fs FileSystem) error {
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
	err = validateAttestationForPublicKeyHash(decodedSubdomainPart, pubKeyHash[:], client, fs)
	if err != nil {
		return fmt.Errorf("failed to validate attestation for public key hash: %w", err)
	}

	log.Println(" -> Public key hash matches REPORT_DATA.")
	log.Println("Certificate validation successful!")
	return nil
}

func verifyFromFile(client HTTPClient, fs FileSystem) {
	certPEM, err := fs.ReadFile("output-keys/certificate.crt")
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
	err = validateCertificate(cert, client, fs)
	if err != nil {
		log.Printf("\n--- Certificate Validation FAILED ---\nError: %v\n", err)
		os.Exit(1)
	} else {
		log.Println("\n--- Certificate Validation SUCCEEDED ---")
	}
}

// queryCTLogs queries the crt.sh API for certificates matching the given domain
func queryCTLogs(domain string, client HTTPClient, fs FileSystem) ([]*x509.Certificate, error) {
	// Construct the crt.sh API URL for initial search
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)

	// Make the HTTP request
	resp, err := httpGetWithRetryAndCaching(url, client, fs)
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
		certResp, err := httpGetWithRetryAndCaching(certURL, client, fs)
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

func verifyFromHttpsRequest(hostname string, client HTTPClient, fs FileSystem) error {
	// Set up TLS configuration
	config := &tls.Config{
		InsecureSkipVerify: true, // We'll verify the certificate ourselves
	}

	// Connect to the server
	conn, err := tls.Dial("tcp", hostname+":443", config)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Get the certificate chain
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no certificates received from server")
	}

	// Get the leaf certificate (first in the chain)
	cert := state.PeerCertificates[0]

	// Run the validation
	return validateCertificate(cert, client, fs)
}

func verifyFromCtLog(hostname string, client HTTPClient, fs FileSystem) error {
	// TODO: Implement CT log verification
	return nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: cert_verifier [live|audit]")
	}

	mode := os.Args[1]
	if mode != "live" && mode != "audit" {
		log.Fatal("First argument must be either 'live' or 'audit'")
	}

	hostname := os.Getenv("VERIFIED_HOST_NAME")
	if hostname == "" {
		log.Fatal("VERIFIED_HOST_NAME environment variable is not set")
	}

	// Create real implementations of dependencies
	client := &http.Client{}
	fs := RealFileSystem{}

	var err error
	if mode == "live" {
		err = verifyFromHttpsRequest(hostname, client, fs)
	} else {
		err = verifyFromCtLog(hostname, client, fs)
	}

	if err != nil {
		log.Printf("\n--- Certificate Validation FAILED ---\nError: %v\n", err)
		os.Exit(1)
	}

	log.Println("\n--- Certificate Validation SUCCEEDED ---")
}
