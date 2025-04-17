package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ddworken/teels/lib"
)

// MockFileSystem implements FileSystem for testing
type MockFileSystem struct {
	Files map[string][]byte
}

func NewMockFileSystem() *MockFileSystem {
	return &MockFileSystem{
		Files: make(map[string][]byte),
	}
}

func (m *MockFileSystem) ReadFile(name string) ([]byte, error) {
	if data, ok := m.Files[name]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}

func (m *MockFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	m.Files[name] = data
	return nil
}

func (m *MockFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return nil
}

// MockHTTPClient implements HTTPClient for testing
type MockHTTPClient struct {
	Response *http.Response
	Error    error
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.Response, nil
}

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T) (*x509.Certificate, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "subdomain.test.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return cert, pemBytes
}

func TestValidateCertificate(t *testing.T) {
	// Set up test environment
	os.Setenv("VERIFIED_HOST_NAME", "example.com")
	defer os.Unsetenv("VERIFIED_HOST_NAME")

	// Generate test certificate
	cert, _ := generateTestCertificate(t)

	// Create mock dependencies
	mockFS := NewMockFileSystem()
	mockClient := &MockHTTPClient{}

	// Test cases
	tests := []struct {
		name          string
		cert          *x509.Certificate
		expectedError string
	}{
		{
			name:          "valid certificate",
			cert:          cert,
			expectedError: "", // No error expected
		},
		{
			name: "invalid DNS names",
			cert: func() *x509.Certificate {
				c := *cert
				c.DNSNames = []string{"wrong.example.com"}
				return &c
			}(),
			expectedError: "expected exactly 2 DNS names",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCertificate(tt.cert, mockClient, mockFS)
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error but got none")
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("error %q does not contain expected string %q", err.Error(), tt.expectedError)
				}
			}
		})
	}
}

func TestValidateAwsNitroAttestation(t *testing.T) {
	// Create mock dependencies
	mockFS := NewMockFileSystem()
	mockClient := &MockHTTPClient{}

	// Create a mock root certificate
	_, rootCertPEM := generateTestCertificate(t)
	mockFS.Files["cert_verifier/aws_nitro_root.pem"] = rootCertPEM

	// Mock the GitHub API response
	mockClient.Response = &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(bytes.NewReader([]byte(`[
			{"tag_name": "v0.1.0"}
		]`))),
	}

	// Create a mock attestation document
	attestationDoc := &lib.AttestationReport{
		AwsNitroAttestation:    []byte(base64.StdEncoding.EncodeToString([]byte("mock attestation"))),
		UnverifiedAttestedData: []byte("test data"),
	}

	// Test cases
	tests := []struct {
		name          string
		attestation   string
		expectedData  []byte
		expectedError string
	}{
		{
			name:          "valid attestation",
			attestation:   string(attestationDoc.AwsNitroAttestation),
			expectedData:  attestationDoc.UnverifiedAttestedData,
			expectedError: "",
		},
		{
			name:          "empty attestation",
			attestation:   "",
			expectedData:  []byte("test data"),
			expectedError: "no AWS Nitro attestation data found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAwsNitroAttestation(tt.attestation, tt.expectedData, mockClient, mockFS)
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error but got none")
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("error %q does not contain expected string %q", err.Error(), tt.expectedError)
				}
			}
		})
	}
}

func TestRetrieveExpectedPcrs(t *testing.T) {
	// Create mock dependencies
	mockFS := NewMockFileSystem()
	mockClient := &MockHTTPClient{}

	// Mock the GitHub API response for releases
	mockClient.Response = &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(bytes.NewReader([]byte(`[
			{"tag_name": "v0.1.0"},
			{"tag_name": "v0.2.0"}
		]`))),
	}

	// Mock the eif-info.txt response
	eifInfo := EifInfo{
		EifVersion: 1,
		Measurements: struct {
			HashAlgorithm string `json:"HashAlgorithm"`
			PCR0          string `json:"PCR0"`
			PCR1          string `json:"PCR1"`
			PCR2          string `json:"PCR2"`
		}{
			HashAlgorithm: "SHA256",
			PCR0:          "0123456789abcdef",
			PCR1:          "fedcba9876543210",
			PCR2:          "aabbccddeeff0011",
		},
	}
	eifInfoJSON, _ := json.Marshal(eifInfo)
	mockClient.Response = &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(eifInfoJSON)),
	}

	// Test cases
	tests := []struct {
		name          string
		client        HTTPClient
		expectedError string
	}{
		{
			name:          "successful retrieval",
			client:        mockClient,
			expectedError: "",
		},
		{
			name: "failed retrieval",
			client: &MockHTTPClient{
				Error: fmt.Errorf("network error"),
			},
			expectedError: "failed to fetch releases",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcrs, err := retrieveExpectedPcrs(tt.client, mockFS)
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(pcrs) == 0 {
					t.Error("expected PCR values but got none")
				}
			} else {
				if err == nil {
					t.Error("expected error but got none")
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("error %q does not contain expected string %q", err.Error(), tt.expectedError)
				}
			}
		})
	}
}
