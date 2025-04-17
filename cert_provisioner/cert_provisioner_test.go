package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ddworken/teels/lib"
	"github.com/go-acme/lego/v4/certcrypto"
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
	if err := os.MkdirAll(outputDir, 0755); err != nil {
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
