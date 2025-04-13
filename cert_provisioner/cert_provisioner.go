package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ddworken/teels/lib"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/mdlayher/vsock"
)

// Config holds the configuration for the certificate provisioner
type Config struct {
	Email           string
	HostName        string
	TLSDirectoryURL string
	TLSKeyType      certcrypto.KeyType
	IsStaging       bool
}

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

// loadConfig loads configuration from environment variables
func loadConfig() (*Config, error) {
	email := os.Getenv("LETS_ENCRYPT_EMAIL_ADDRESS")
	if email == "" {
		return nil, fmt.Errorf("environment variable LETS_ENCRYPT_EMAIL_ADDRESS must be set")
	}

	hostName := os.Getenv("VERIFIED_HOST_NAME")
	if hostName == "" {
		return nil, fmt.Errorf("environment variable VERIFIED_HOST_NAME must be set")
	}

	tlsKeyType := os.Getenv("TLS_KEY_TYPE")
	if tlsKeyType == "" {
		tlsKeyType = "EC256"
	}

	keyType, err := parseTLSKeyType(tlsKeyType)
	if err != nil {
		return nil, err
	}

	return &Config{
		Email:           email,
		HostName:        hostName,
		TLSDirectoryURL: lego.LEDirectoryStaging, // Default to staging for safety
		TLSKeyType:      keyType,
		IsStaging:       true,
	}, nil
}

func parseTLSKeyType(keyType string) (certcrypto.KeyType, error) {
	switch strings.ToUpper(keyType) {
	case "EC256":
		return certcrypto.EC256, nil
	case "EC384":
		return certcrypto.EC384, nil
	case "RSA2048":
		return certcrypto.RSA2048, nil
	case "RSA4096":
		return certcrypto.RSA4096, nil
	case "RSA8192":
		return certcrypto.RSA8192, nil
	default:
		return certcrypto.EC256, fmt.Errorf("invalid TLS_KEY_TYPE '%s'. Valid options are: EC256, EC384, RSA2048, RSA4096, RSA8192", keyType)
	}
}

func createAwsNitroAttestation(data []byte) ([]byte, error) {
	attestation := lib.AttestationReport{
		UnverifiedAttestedData: data,
		AwsNitroAttestation:    nil,
	}

	// Set the environment variable for user data
	os.Setenv("NSM_USER_DATA", string(data))

	// Run the nsm-cli binary and capture its output
	cmd := exec.Command("./nsm-cli")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run nsm-cli: %w", err)
	}

	// The output is base64 encoded, so decode it
	attestation.AwsNitroAttestation, err = base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to decode nsm-cli output: %w", err)
	}

	return saveAttestation(attestation)
}

func createFakeAttestation(data []byte) ([]byte, error) {
	attestation := lib.AttestationReport{
		UnverifiedAttestedData: data,
		AwsNitroAttestation:    nil,
	}
	log.Printf("Fake attestation data: %x", attestation.UnverifiedAttestedData)
	return saveAttestation(attestation)
}

func saveAttestation(attestation lib.AttestationReport) ([]byte, error) {
	jsonData, err := json.Marshal(attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation to JSON: %w", err)
	}

	hash := sha256.Sum256(jsonData)

	outputDir := "output-attestations"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	outputPath := filepath.Join(outputDir, lib.Base32Encoder.EncodeToString(hash[:])+".bin")
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write attestation file: %w", err)
	}

	log.Printf("Generated attestation report and saved to: %s", outputPath)
	return jsonData, nil
}

func loadOrGenerateAccountKey() (*ecdsa.PrivateKey, error) {
	accountKeyPath := filepath.Join("output-keys", "account_key.pem")

	if _, err := os.Stat(accountKeyPath); err == nil {
		keyData, err := os.ReadFile(accountKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read account key file: %w", err)
		}

		block, _ := pem.Decode(keyData)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block from account key file")
		}

		accountPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse account private key: %w", err)
		}
		log.Println("Loaded existing ECDSA P-256 account private key from file.")
		return accountPrivateKey, nil
	}

	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account private key: %w", err)
	}
	log.Println("Generated new ECDSA P-256 account private key.")

	if err := os.MkdirAll("output-keys", 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	accountPrivKeyBytes, err := x509.MarshalECPrivateKey(accountPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal account private key: %w", err)
	}

	accountPrivKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: accountPrivKeyBytes})
	if err := os.WriteFile(accountKeyPath, accountPrivKeyPem, 0600); err != nil {
		return nil, fmt.Errorf("failed to write account_key.pem: %w", err)
	}
	log.Println("Saved new account private key to output-keys/account_key.pem")

	return accountPrivateKey, nil
}

func generateCertificateKey() (*ecdsa.PrivateKey, []byte, error) {
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate private key: %w", err)
	}
	log.Println("Generated ECDSA P-256 certificate private key.")

	certPublicKey := &certPrivateKey.PublicKey
	certPublicKeyBytes, err := x509.MarshalPKIXPublicKey(certPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal certificate public key: %w", err)
	}
	log.Printf("Marshalled certificate public key (X.509 PKIX format): %d bytes\n", len(certPublicKeyBytes))

	return certPrivateKey, certPublicKeyBytes, nil
}

func setupLegoClient(config *Config, accountKey *ecdsa.PrivateKey) (*lego.Client, error) {
	myUser := &MyUser{
		Email: config.Email,
		key:   accountKey,
	}

	// Add hosts entry if it doesn't exist
	hostsEntry := "127.0.0.1 acme-staging-v02.api.letsencrypt.org"
	hostsContent, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/hosts: %w", err)
	}

	if !strings.Contains(string(hostsContent), hostsEntry) {
		// Open file in append mode
		hostsFile, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open /etc/hosts for writing: %w", err)
		}
		defer hostsFile.Close()

		// Add the new entry
		if _, err := hostsFile.WriteString("\n" + hostsEntry + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write to /etc/hosts: %w", err)
		}
		log.Println("Added Let's Encrypt staging API entry to /etc/hosts")
	}

	legoConfig := lego.NewConfig(myUser)
	legoConfig.CADirURL = config.TLSDirectoryURL
	legoConfig.Certificate.KeyType = config.TLSKeyType

	// Test the connection to Let's Encrypt staging API
	resp, err := legoConfig.HTTPClient.Get(config.TLSDirectoryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Let's Encrypt staging API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("let's encrypt API returned non-200 status code: %d", resp.StatusCode)
	}

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Configure the HTTP-01 provider to listen on vsock
	http01Provider := http01.NewProviderServer("", "80")
	http01Provider.SetListenerCreator(func() (net.Listener, error) {
		return vsock.Listen(80, nil)
	})
	if err := client.Challenge.SetHTTP01Provider(http01Provider); err != nil {
		return nil, fmt.Errorf("failed to set HTTP-01 provider: %w", err)
	}

	return client, nil
}

func registerAccount(client *lego.Client, user *MyUser) error {
	if user.GetRegistration() == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("failed to register ACME account: %w", err)
		}
		user.Registration = reg
		log.Println("ACME account registration successful.")
	} else {
		log.Println("ACME account already registered.")
	}
	return nil
}

func saveArtifacts(certificates *certificate.Resource, accountKey *ecdsa.PrivateKey) error {
	outputDir := "/app/output-keys"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	filePermsPrivate := os.FileMode(0600)
	filePermsPublic := os.FileMode(0644)

	// Save account private key
	accountPrivKeyBytes, err := x509.MarshalECPrivateKey(accountKey)
	if err != nil {
		return fmt.Errorf("failed to marshal account private key: %w", err)
	}
	accountPrivKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: accountPrivKeyBytes})
	if err := os.WriteFile(filepath.Join(outputDir, "account_key.pem"), accountPrivKeyPem, filePermsPrivate); err != nil {
		return fmt.Errorf("failed to write account_key.pem: %w", err)
	}

	// Save certificate
	if err := os.WriteFile(filepath.Join(outputDir, "certificate.crt"), certificates.Certificate, filePermsPublic); err != nil {
		return fmt.Errorf("failed to write certificate.crt: %w", err)
	}

	// Save certificate private key
	if err := os.WriteFile(filepath.Join(outputDir, "certificate_key.pem"), certificates.PrivateKey, filePermsPrivate); err != nil {
		return fmt.Errorf("failed to write certificate_key.pem: %w", err)
	}

	return nil
}

func sleepingLogFatalf(format string, args ...interface{}) {
	if closeListener != nil {
		closeListener()
	}
	log.Printf(format, args...)
	// time.Sleep(30 * time.Second)

	cmd := exec.Command("/app/enclave-server")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to execute command: %v", err)
	}

	// time.Sleep(10 * time.Second)
	// log.Fatalf(format, args...)
}

func runSocatCommand(stdoutFile, stderrFile *os.File, args ...string) error {
	cmd := exec.Command("socat", args...)
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile

	// Start the command in the background
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start socat command: %w", err)
	}

	// Create a channel to receive the error
	errChan := make(chan error, 1)
	go func() {
		errChan <- cmd.Wait()
	}()

	// Wait for 2 seconds or for the command to exit
	select {
	case err := <-errChan:
		// Command exited within 2 seconds, return the error
		return fmt.Errorf("socat command exited early: %w", err)
	case <-time.After(2 * time.Second):
		// Command is still running after 2 seconds, return nil
		return nil
	}
}

func startBackgroundTcpProxy() error {
	// Configure loopback interface and routing
	cmd := exec.Command("ifconfig", "lo", "127.0.0.1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure loopback interface: %w", err)
	}

	cmd = exec.Command("ip", "route", "add", "default", "dev", "lo", "src", "127.0.0.1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add default route: %w", err)
	}

	// Bring up the loopback interface and create a virtual interface
	cmd = exec.Command("ip", "link", "set", "lo", "up")
	cmd.Run() // Ignore errors for this command
	cmd = exec.Command("ip", "link", "set", "dev", "lo:0", "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up lo:0 interface: %w", err)
	}

	// Create stdout and stderr files
	stdoutFile, err := os.OpenFile("/app/static/proxy_stdout.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to create stdout file: %w", err)
	}
	// defer stdoutFile.Close()

	stderrFile, err := os.OpenFile("/app/static/proxy_stderr.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to create stderr file: %w", err)
	}
	// defer stderrFile.Close()

	return runSocatCommand(stdoutFile, stderrFile, "-v", "-v", "tcp-listen:443,bind=127.0.0.1,fork,reuseaddr", "vsock-connect:2:8002")
}

func setupDualLogger() (*os.File, error) {
	// Create the log file
	logFile, err := os.OpenFile("/app/static/log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// If the directory doesn't exist, don't log to it
		return nil, nil
	}

	// Create a multi-writer that writes to both stdout and the log file
	multiWriter := io.MultiWriter(os.Stdout, logFile)

	// Set the log output to the multi-writer
	log.SetOutput(multiWriter)

	return logFile, nil
}

var closeListener func()

func main() {
	// Set up dual logging
	logFile, err := setupDualLogger()
	if err != nil {
		log.Fatalf("Failed to set up logging: %v", err)
	}
	if logFile != nil {
		defer logFile.Close()
	}

	log.Println("Starting certificate provisioning process...")

	err = startBackgroundTcpProxy()
	if err != nil {
		sleepingLogFatalf("Failed to start background TCP proxy: %v", err)
	}

	config, err := loadConfig()
	if err != nil {
		sleepingLogFatalf("Failed to load configuration: %v", err)
	}

	accountKey, err := loadOrGenerateAccountKey()
	if err != nil {
		sleepingLogFatalf("Failed to load/generate account key: %v", err)
	}

	certPrivateKey, certPublicKeyBytes, err := generateCertificateKey()
	if err != nil {
		sleepingLogFatalf("Failed to generate certificate key: %v", err)
	}

	certPublicKeyHash := sha256.Sum256(certPublicKeyBytes)
	certAttestationReport, err := createFakeAttestation(certPublicKeyHash[:])
	if err != nil {
		sleepingLogFatalf("Failed to generate attestation: %v", err)
	}

	certAttestationHash := sha256.Sum256(certAttestationReport)
	certBase32Encoder := lib.Base32Encoder
	certEncodedAttestationHash := strings.ToLower(certBase32Encoder.EncodeToString(certAttestationHash[:]))

	certSubdomain := certEncodedAttestationHash + "." + config.HostName
	fmt.Printf("certSubdomain: %v\n", certSubdomain)
	certTargetDomains := []string{config.HostName, certSubdomain}
	fmt.Printf("certTargetDomains: %v\n", certTargetDomains)

	client, err := setupLegoClient(config, accountKey)
	if err != nil {
		sleepingLogFatalf("Failed to setup Lego client: %v", err)
	}

	myUser := &MyUser{
		Email: config.Email,
		key:   accountKey,
	}
	fmt.Printf("myUser: %v\n", myUser)

	if err := registerAccount(client, myUser); err != nil {
		sleepingLogFatalf("Failed to register account: %v", err)
	}

	request := certificate.ObtainRequest{
		Domains:    certTargetDomains,
		Bundle:     true,
		PrivateKey: certPrivateKey,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		sleepingLogFatalf("Failed to obtain certificate: %v\nCheck network connectivity, port forwarding, and firewall rules.\nEnsure the domains %v correctly resolve to this machine's public IP.",
			err, request.Domains)
	}

	if err := saveArtifacts(certificates, accountKey); err != nil {
		sleepingLogFatalf("Failed to save artifacts: %v", err)
	}

	log.Println("\n--- Process Complete ---")
	log.Printf("Successfully obtained and saved certificate and related artifacts for: %v\n", certTargetDomains)

	// If command-line arguments are provided, execute them as a command
	// if len(os.Args) > 1 {
	if closeListener != nil {
		closeListener()
	}
	cmd := exec.Command("/app/enclave-server")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		sleepingLogFatalf("Failed to execute command: %v", err)
	}
	// }
}
