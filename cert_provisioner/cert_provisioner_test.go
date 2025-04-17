package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ddworken/teels/lib"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/registration"
)

func TestParseTLSKeyType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected certcrypto.KeyType
		wantErr  bool
	}{
		{
			name:     "Valid EC256",
			input:    "EC256",
			expected: certcrypto.EC256,
			wantErr:  false,
		},
		{
			name:     "Valid EC384",
			input:    "EC384",
			expected: certcrypto.EC384,
			wantErr:  false,
		},
		{
			name:     "Valid RSA2048",
			input:    "RSA2048",
			expected: certcrypto.RSA2048,
			wantErr:  false,
		},
		{
			name:     "Invalid type",
			input:    "INVALID",
			expected: certcrypto.EC256,
			wantErr:  true,
		},
		{
			name:     "Case insensitive",
			input:    "ec256",
			expected: certcrypto.EC256,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTLSKeyType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTLSKeyType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("parseTLSKeyType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGenerateCertificateKey(t *testing.T) {
	privateKey, publicKeyBytes, err := generateCertificateKey()
	if err != nil {
		t.Fatalf("generateCertificateKey() error = %v", err)
	}

	// Verify the private key is ECDSA P-256
	if privateKey.Curve != elliptic.P256() {
		t.Errorf("generateCertificateKey() private key curve = %v, want %v", privateKey.Curve, elliptic.P256())
	}

	// Verify the public key bytes can be parsed
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to parse generated public key: %v", err)
	}

	// Verify the public key matches the private key
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Generated public key is not ECDSA")
	}

	if !ecdsaPublicKey.Equal(&privateKey.PublicKey) {
		t.Error("Generated public key does not match private key")
	}
}

func TestLoadConfig(t *testing.T) {
	// Save original environment variables
	originalEmail := os.Getenv("LETS_ENCRYPT_EMAIL_ADDRESS")
	originalHost := os.Getenv("VERIFIED_HOST_NAME")
	originalKeyType := os.Getenv("TLS_KEY_TYPE")

	// Clean up after test
	defer func() {
		os.Setenv("LETS_ENCRYPT_EMAIL_ADDRESS", originalEmail)
		os.Setenv("VERIFIED_HOST_NAME", originalHost)
		os.Setenv("TLS_KEY_TYPE", originalKeyType)
	}()

	tests := []struct {
		name        string
		setupEnv    func()
		wantErr     bool
		checkConfig func(*Config) error
	}{
		{
			name: "Valid configuration",
			setupEnv: func() {
				os.Setenv("LETS_ENCRYPT_EMAIL_ADDRESS", "test@example.com")
				os.Setenv("VERIFIED_HOST_NAME", "example.com")
				os.Setenv("TLS_KEY_TYPE", "EC256")
			},
			wantErr: false,
			checkConfig: func(c *Config) error {
				if c.Email != "test@example.com" {
					return fmt.Errorf("Email = %v, want %v", c.Email, "test@example.com")
				}
				if c.HostName != "example.com" {
					return fmt.Errorf("HostName = %v, want %v", c.HostName, "example.com")
				}
				if c.TLSKeyType != certcrypto.EC256 {
					return fmt.Errorf("TLSKeyType = %v, want %v", c.TLSKeyType, certcrypto.EC256)
				}
				return nil
			},
		},
		{
			name: "Missing email",
			setupEnv: func() {
				os.Unsetenv("LETS_ENCRYPT_EMAIL_ADDRESS")
				os.Setenv("VERIFIED_HOST_NAME", "example.com")
			},
			wantErr: true,
		},
		{
			name: "Missing hostname",
			setupEnv: func() {
				os.Setenv("LETS_ENCRYPT_EMAIL_ADDRESS", "test@example.com")
				os.Unsetenv("VERIFIED_HOST_NAME")
			},
			wantErr: true,
		},
		{
			name: "Default key type",
			setupEnv: func() {
				os.Setenv("LETS_ENCRYPT_EMAIL_ADDRESS", "test@example.com")
				os.Setenv("VERIFIED_HOST_NAME", "example.com")
				os.Unsetenv("TLS_KEY_TYPE")
			},
			wantErr: false,
			checkConfig: func(c *Config) error {
				if c.TLSKeyType != certcrypto.EC256 {
					return fmt.Errorf("TLSKeyType = %v, want %v (default)", c.TLSKeyType, certcrypto.EC256)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment
			tt.setupEnv()

			// Run test
			config, err := loadConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("loadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If we expect no error, check the config
			if !tt.wantErr && tt.checkConfig != nil {
				if err := tt.checkConfig(config); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestMyUser(t *testing.T) {
	// Generate a test private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	// Create a test registration resource
	reg := &registration.Resource{
		URI: "https://example.com/reg/123",
	}

	tests := []struct {
		name     string
		user     *MyUser
		checkGet func(*MyUser) error
	}{
		{
			name: "Basic user",
			user: &MyUser{
				Email:        "test@example.com",
				Registration: reg,
				key:          privateKey,
			},
			checkGet: func(u *MyUser) error {
				if u.GetEmail() != "test@example.com" {
					return fmt.Errorf("GetEmail() = %v, want %v", u.GetEmail(), "test@example.com")
				}
				if u.GetRegistration() != reg {
					return fmt.Errorf("GetRegistration() returned different registration resource")
				}
				if u.GetPrivateKey() != privateKey {
					return fmt.Errorf("GetPrivateKey() returned different private key")
				}
				return nil
			},
		},
		{
			name: "User with nil registration",
			user: &MyUser{
				Email:        "test@example.com",
				Registration: nil,
				key:          privateKey,
			},
			checkGet: func(u *MyUser) error {
				if u.GetRegistration() != nil {
					return fmt.Errorf("GetRegistration() = %v, want nil", u.GetRegistration())
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.checkGet(tt.user); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestSaveAttestation(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "attestation-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create the output directory within the temp directory
	outputDir := filepath.Join(tempDir, "output-attestations")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}

	// Override the output directory for testing
	originalOutputDir := "/app/static/output-attestations"
	defer func() {
		os.Setenv("ATTESTATION_OUTPUT_DIR", originalOutputDir)
	}()
	os.Setenv("ATTESTATION_OUTPUT_DIR", outputDir)

	// Create test data
	testData := []byte("test attestation data")
	attestation := lib.AttestationReport{
		UnverifiedAttestedData: testData,
		AwsNitroAttestation:    []byte("test nitro attestation"),
	}

	tests := []struct {
		name        string
		attestation lib.AttestationReport
		wantErr     bool
		checkFile   func(string) error
	}{
		{
			name:        "Valid attestation",
			attestation: attestation,
			wantErr:     false,
			checkFile: func(outputPath string) error {
				// Read the saved file
				data, err := os.ReadFile(outputPath)
				if err != nil {
					return fmt.Errorf("failed to read saved file: %v", err)
				}

				// Verify the content
				var savedAttestation lib.AttestationReport
				if err := json.Unmarshal(data, &savedAttestation); err != nil {
					return fmt.Errorf("failed to unmarshal saved attestation: %v", err)
				}

				if string(savedAttestation.UnverifiedAttestedData) != string(testData) {
					return fmt.Errorf("saved attestation data mismatch")
				}

				// Verify the filename is correct (based on hash)
				hash := sha256.Sum256(data)
				expectedFilename := lib.Base32Encoder.EncodeToString(hash[:]) + ".bin"
				if filepath.Base(outputPath) != expectedFilename {
					return fmt.Errorf("filename mismatch: got %v, want %v", filepath.Base(outputPath), expectedFilename)
				}

				return nil
			},
		},
		{
			name: "Empty attestation",
			attestation: lib.AttestationReport{
				UnverifiedAttestedData: []byte{},
				AwsNitroAttestation:    []byte{},
			},
			wantErr: false,
			checkFile: func(outputPath string) error {
				data, err := os.ReadFile(outputPath)
				if err != nil {
					return fmt.Errorf("failed to read saved file: %v", err)
				}

				var savedAttestation lib.AttestationReport
				if err := json.Unmarshal(data, &savedAttestation); err != nil {
					return fmt.Errorf("failed to unmarshal saved attestation: %v", err)
				}

				if len(savedAttestation.UnverifiedAttestedData) != 0 {
					return fmt.Errorf("expected empty attestation data")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save the attestation
			jsonData, err := saveAttestation(tt.attestation)
			if (err != nil) != tt.wantErr {
				t.Errorf("saveAttestation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Calculate the expected output path
				hash := sha256.Sum256(jsonData)
				filename := lib.Base32Encoder.EncodeToString(hash[:]) + ".bin"
				outputPath := filepath.Join(outputDir, filename)

				// Check if the file exists
				if _, err := os.Stat(outputPath); os.IsNotExist(err) {
					t.Errorf("output file %s does not exist", outputPath)
					return
				}

				// Run additional checks if provided
				if tt.checkFile != nil {
					if err := tt.checkFile(outputPath); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
}

func TestLoadOrGenerateAccountKey(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "account-key-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Override the output directory for testing
	originalOutputDir := "output-keys"
	defer func() {
		os.Setenv("OUTPUT_KEYS_DIR", originalOutputDir)
	}()
	os.Setenv("OUTPUT_KEYS_DIR", tempDir)

	tests := []struct {
		name     string
		setup    func() error
		checkKey func(*ecdsa.PrivateKey) error
		wantErr  bool
	}{
		{
			name: "Generate new key",
			setup: func() error {
				// No setup needed - will generate new key
				return nil
			},
			checkKey: func(key *ecdsa.PrivateKey) error {
				if key.Curve != elliptic.P256() {
					return fmt.Errorf("key curve = %v, want %v", key.Curve, elliptic.P256())
				}
				return nil
			},
			wantErr: false,
		},
		{
			name: "Load existing key",
			setup: func() error {
				// Generate and save a key first
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return err
				}

				keyBytes, err := x509.MarshalECPrivateKey(key)
				if err != nil {
					return err
				}

				keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
				return os.WriteFile(filepath.Join(tempDir, "account_key.pem"), keyPem, 0o600)
			},
			checkKey: func(key *ecdsa.PrivateKey) error {
				if key.Curve != elliptic.P256() {
					return fmt.Errorf("key curve = %v, want %v", key.Curve, elliptic.P256())
				}
				return nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			key, err := loadOrGenerateAccountKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("loadOrGenerateAccountKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.checkKey != nil {
				if err := tt.checkKey(key); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestSaveArtifacts(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "artifacts-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Override the output directory for testing
	originalOutputDir := os.Getenv("OUTPUT_KEYS_DIR")
	defer func() {
		os.Setenv("OUTPUT_KEYS_DIR", originalOutputDir)
	}()
	os.Setenv("OUTPUT_KEYS_DIR", tempDir)

	// Generate test keys and certificate
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate account key: %v", err)
	}

	// Create test certificate
	cert := &certificate.Resource{
		Certificate: []byte("test certificate"),
		PrivateKey:  []byte("test private key"),
	}

	tests := []struct {
		name       string
		cert       *certificate.Resource
		accountKey *ecdsa.PrivateKey
		checkFiles func(string) error
		wantErr    bool
	}{
		{
			name:       "Valid artifacts",
			cert:       cert,
			accountKey: accountKey,
			checkFiles: func(outputDir string) error {
				// Check account key file
				accountKeyPath := filepath.Join(outputDir, "account_key.pem")
				if _, err := os.Stat(accountKeyPath); os.IsNotExist(err) {
					return fmt.Errorf("account key file does not exist")
				}

				// Check certificate file
				certPath := filepath.Join(outputDir, "certificate.crt")
				if _, err := os.Stat(certPath); os.IsNotExist(err) {
					return fmt.Errorf("certificate file does not exist")
				}

				// Check certificate key file
				certKeyPath := filepath.Join(outputDir, "certificate_key.pem")
				if _, err := os.Stat(certKeyPath); os.IsNotExist(err) {
					return fmt.Errorf("certificate key file does not exist")
				}

				return nil
			},
			wantErr: false,
		},
		{
			name:       "Nil certificate",
			cert:       nil,
			accountKey: accountKey,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := saveArtifacts(tt.cert, tt.accountKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("saveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.checkFiles != nil {
				if err := tt.checkFiles(tempDir); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestCreateAwsNitroAttestation(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "attestation-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Override the output directory for testing
	originalOutputDir := "/app/static/output-attestations"
	defer func() {
		os.Setenv("ATTESTATION_OUTPUT_DIR", originalOutputDir)
	}()
	os.Setenv("ATTESTATION_OUTPUT_DIR", tempDir)

	// Create a mock command that just echoes the environment variable
	mockCmdPath := filepath.Join(tempDir, "mock-nsm-cli")
	mockCmdContent := `#!/bin/sh
echo "Mock attestation for $NSM_USER_DATA"
`
	if err := os.WriteFile(mockCmdPath, []byte(mockCmdContent), 0o755); err != nil {
		t.Fatalf("Failed to create mock command: %v", err)
	}

	// Override the NSM_CLI_PATH for testing
	originalNsmCliPath := os.Getenv("NSM_CLI_PATH")
	defer func() {
		os.Setenv("NSM_CLI_PATH", originalNsmCliPath)
	}()
	os.Setenv("NSM_CLI_PATH", mockCmdPath)

	tests := []struct {
		name    string
		data    []byte
		check   func([]byte) error
		wantErr bool
	}{
		{
			name: "Valid attestation",
			data: []byte("test data"),
			check: func(attestation []byte) error {
				if len(attestation) == 0 {
					return fmt.Errorf("attestation is empty")
				}
				return nil
			},
			wantErr: false,
		},
		{
			name:    "Empty data",
			data:    []byte{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation, err := createAwsNitroAttestation(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("createAwsNitroAttestation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				if err := tt.check(attestation); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestCreateFakeAttestation(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "attestation-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Override the output directory for testing
	originalOutputDir := "/app/static/output-attestations"
	defer func() {
		os.Setenv("ATTESTATION_OUTPUT_DIR", originalOutputDir)
	}()
	os.Setenv("ATTESTATION_OUTPUT_DIR", tempDir)

	tests := []struct {
		name    string
		data    []byte
		check   func([]byte) error
		wantErr bool
	}{
		{
			name: "Valid attestation",
			data: []byte("test data"),
			check: func(attestation []byte) error {
				if len(attestation) == 0 {
					return fmt.Errorf("attestation is empty")
				}
				return nil
			},
			wantErr: false,
		},
		{
			name:    "Empty data",
			data:    []byte{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation, err := createFakeAttestation(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("createFakeAttestation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				if err := tt.check(attestation); err != nil {
					t.Error(err)
				}
			}
		})
	}
}
