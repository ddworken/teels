package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ddworken/teels/lib"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// MyUser implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func attest(data []byte) []byte {
	attestation := lib.FakeAttestation{
		AttestedData: data,
	}
	log.Printf("Attestation data: %x", attestation.AttestedData)

	// Serialize to JSON
	jsonData, err := json.Marshal(attestation)
	if err != nil {
		log.Fatalf("FATAL: Failed to marshal attestation to JSON: %v", err)
	}

	// Calculate SHA256 hash of the JSON
	hash := sha256.Sum256(jsonData)

	// Create output directory if it doesn't exist
	outputDir := "output-attestations"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("FATAL: Failed to create output directory: %v", err)
	}

	// Write the JSON to a file named with the hash
	outputPath := filepath.Join(outputDir, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])+".bin")
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		log.Fatalf("FATAL: Failed to write attestation file: %v", err)
	}

	log.Printf("Generated attestation report and saved to: %s", outputPath)
	return jsonData
}

func main() {
	log.Println("Starting certificate provisioning process...")

	// --- 1. Get Configuration ---
	email := os.Getenv("LETS_ENCRYPT_EMAIL_ADDRESS")
	if email == "" {
		log.Fatal("FATAL: Environment variable LETS_ENCRYPT_EMAIL_ADDRESS must be set")
	}
	log.Printf("Using Let's Encrypt email: %s\n", email)

	hostName := os.Getenv("VERIFIED_HOST_NAME")
	if hostName == "" {
		log.Fatal("FATAL: Environment variable VERIFIED_HOST_NAME must be set")
	}
	log.Printf("Using host name: %s\n", hostName)

	// --- 2. Generate Account Key ---
	// Create a user account private key. Let's Encrypt requires this for registration.
	// Using ECDSA P-256 as it's common and efficient.
	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("FATAL: Failed to generate account private key: %v", err)
	}
	log.Println("Generated ECDSA P-256 account private key.")

	// --- 3. Calculate Public Key and Hash ---
	// Get the public key associated with the account private key.
	accountPublicKey := &accountPrivateKey.PublicKey
	// Marshal the public key into DER-encoded PKIX format (standard).
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(accountPublicKey)
	if err != nil {
		log.Fatalf("FATAL: Failed to marshal public key: %v", err)
	}
	log.Printf("Marshalled public key (X.509 PKIX format): %d bytes\n", len(publicKeyBytes))

	// Calculate the SHA256 hash of the public key bytes.
	publicKeyHash := sha256.Sum256(publicKeyBytes)
	log.Printf("Calculated SHA256 hash of public key: %x\n", publicKeyHash)

	// --- 4. Attest to the Public Key Hash ---
	// Pass the hash to the (placeholder) attestation function.
	// In a real scenario, this binds the TEE's identity to the public key.
	attestationReport := attest(publicKeyHash[:]) // Pass the hash slice

	// --- 5. Hash the Attestation Report ---
	// Calculate the SHA256 hash of the entire attestation report.
	attestationHash := sha256.Sum256(attestationReport)
	log.Printf("Calculated SHA256 hash of attestation report: %x\n", attestationHash)

	// --- 6. Create Subdomain from Attestation Hash ---
	// Encode the attestation hash using URL-safe Base32 without padding.
	// Let's Encrypt prefers lowercase domain names.
	base32Encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	encodedAttestationHash := strings.ToLower(base32Encoder.EncodeToString(attestationHash[:]))
	log.Printf("Calculated SHA256 hash of attestation report, encoded: %s\n", encodedAttestationHash)

	// Construct the target domains.
	subdomain := encodedAttestationHash + "." + hostName
	primaryDomain := hostName
	targetDomains := []string{subdomain, primaryDomain}
	log.Printf("Target domains for certificate: %v\n", targetDomains)

	// --- 7. Configure Let's Encrypt Client ---
	myUser := MyUser{
		Email: email,
		key:   accountPrivateKey,
	}

	config := lego.NewConfig(&myUser)

	// !! IMPORTANT !! Use Staging for testing, Production for real certs.
	// config.CADirURL = lego.LEDirectoryProduction
	config.CADirURL = lego.LEDirectoryStaging // SAFER FOR TESTING
	log.Printf("Using Let's Encrypt directory URL: %s\n", config.CADirURL)

	// Configure the type of key used for the *certificate* itself.
	// RSA 2048 is common, but EC256/EC384 are also good options.
	config.Certificate.KeyType = certcrypto.RSA2048 // Or certcrypto.EC256, etc.
	log.Printf("Requesting certificate with key type: %s\n", config.Certificate.KeyType)

	// Create the Let's Encrypt client.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatalf("FATAL: Failed to create ACME client: %v", err)
	}

	// --- 8. Set up Challenge Providers ---
	// Configure how Let's Encrypt can verify domain ownership.
	log.Printf("Setting up HTTP-01 challenge provider on port 80")
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	if err != nil {
		log.Fatalf("FATAL: Failed to set HTTP01 provider: %v", err)
	}

	log.Printf("Setting up TLS-ALPN-01 challenge provider on port 443")
	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "443"))
	if err != nil {
		log.Fatalf("FATAL: Failed to set TLSALPN01 provider: %v", err)
	}

	// --- 9. Register Account ---
	// Register the account with Let's Encrypt if it's new.
	log.Println("Registering ACME account...")
	// Check if registration exists, otherwise register
	if myUser.GetRegistration() == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatalf("FATAL: Failed to register ACME account: %v", err)
		}
		myUser.Registration = reg
		log.Println("ACME account registration successful.")
	} else {
		log.Println("ACME account already registered.")
	}

	// --- 10. Obtain Certificate ---
	// Request the certificate for the specified domains.
	request := certificate.ObtainRequest{
		Domains: targetDomains,
		Bundle:  true, // Bundle includes the intermediate certificate.
	}
	log.Printf("Requesting certificate for domains: %v\n", request.Domains)
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		// Log detailed error if challenge fails
		log.Fatalf("FATAL: Failed to obtain certificate: %v\n"+
			"Check network connectivity, port forwarding, and firewall rules.\n"+
			"Ensure the domains %v correctly resolve to this machine's public IP.",
			err, request.Domains)
	}
	log.Println("Successfully obtained certificate.")
	log.Printf("Certificate URL: %s\n", certificates.CertURL)

	// --- 11. Parse Certificate and Calculate Public Key Hash ---
	// Parse the certificate to get its public key
	certBlock, _ := pem.Decode(certificates.Certificate)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		log.Fatal("FATAL: Failed to decode certificate PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Fatalf("FATAL: Failed to parse certificate: %v", err)
	}

	// Marshal the certificate's public key into DER-encoded PKIX format
	certPublicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		log.Fatalf("FATAL: Failed to marshal certificate public key: %v", err)
	}
	log.Printf("Marshalled certificate public key (X.509 PKIX format): %d bytes\n", len(certPublicKeyBytes))

	// Calculate the SHA256 hash of the public key bytes
	certPublicKeyHash := sha256.Sum256(certPublicKeyBytes)
	log.Printf("Calculated SHA256 hash of certificate public key: %x\n", certPublicKeyHash)

	// --- 12. Attest to the Certificate's Public Key Hash ---
	// Pass the hash to the attestation function
	certAttestationReport := attest(certPublicKeyHash[:]) // Pass the hash slice

	// --- 13. Hash the Attestation Report ---
	// Calculate the SHA256 hash of the entire attestation report
	certAttestationHash := sha256.Sum256(certAttestationReport)
	log.Printf("Calculated SHA256 hash of attestation report: %x\n", certAttestationHash)

	// --- 14. Create Subdomain from Attestation Hash ---
	// Encode the attestation hash using URL-safe Base32 without padding
	// Let's Encrypt prefers lowercase domain names
	certBase32Encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	certEncodedAttestationHash := strings.ToLower(certBase32Encoder.EncodeToString(certAttestationHash[:]))
	log.Printf("Calculated SHA256 hash of attestation report, encoded: %s\n", certEncodedAttestationHash)

	// Construct the target domains
	certSubdomain := certEncodedAttestationHash + "." + hostName
	certPrimaryDomain := hostName
	certTargetDomains := []string{certSubdomain, certPrimaryDomain}
	log.Printf("Target domains for certificate: %v\n", certTargetDomains)

	// --- 15. Create Output Directory ---
	outputDir := "output-keys"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("FATAL: Failed to create output directory: %v", err)
	}
	log.Printf("Created output directory: %s", outputDir)

	// --- 16. Save Artifacts ---
	filePermsPrivate := os.FileMode(0600) // Read/write for owner only
	filePermsPublic := os.FileMode(0644)  // Read for all, write for owner

	// a) Account Private Key (PEM format)
	accountPrivKeyBytes, err := x509.MarshalECPrivateKey(accountPrivateKey)
	if err != nil {
		log.Fatalf("FATAL: Failed to marshal account private key: %v", err)
	}
	accountPrivKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: accountPrivKeyBytes})
	err = os.WriteFile(filepath.Join(outputDir, "account_key.pem"), accountPrivKeyPem, filePermsPrivate)
	if err != nil {
		log.Fatalf("FATAL: Failed to write account_key.pem: %v", err)
	}
	log.Println("Saved account private key to output-keys/account_key.pem")

	// b) Public Key (PEM format)
	publicKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
	err = os.WriteFile(filepath.Join(outputDir, "public_key.pem"), publicKeyPem, filePermsPublic)
	if err != nil {
		log.Fatalf("FATAL: Failed to write public_key.pem: %v", err)
	}
	log.Println("Saved public key to output-keys/public_key.pem")

	// c) Certificate (PEM format - includes leaf + intermediate chain)
	err = os.WriteFile(filepath.Join(outputDir, "certificate.crt"), certificates.Certificate, filePermsPublic)
	if err != nil {
		log.Fatalf("FATAL: Failed to write certificate.crt: %v", err)
	}
	log.Println("Saved certificate chain to output-keys/certificate.crt")

	// d) Certificate's Private Key (PEM format)
	// This key corresponds to the certificate, generated based on config.Certificate.KeyType.
	err = os.WriteFile(filepath.Join(outputDir, "certificate_key.pem"), certificates.PrivateKey, filePermsPrivate)
	if err != nil {
		log.Fatalf("FATAL: Failed to write certificate_key.pem: %v", err)
	}
	log.Println("Saved certificate's private key to output-keys/certificate_key.pem")

	log.Println("\n--- Process Complete ---")
	log.Printf("Successfully obtained and saved certificate and related artifacts for: %v\n", certTargetDomains)
}
