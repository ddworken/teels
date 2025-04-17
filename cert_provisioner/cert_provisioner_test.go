package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
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
