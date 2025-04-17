package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
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
	DoFunc   func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	if m.Error != nil {
		return nil, m.Error
	}
	return m.Response, nil
}

func TestRetrieveExpectedPcrs(t *testing.T) {
	// Create mock dependencies
	mockFS := NewMockFileSystem()

	// Create a mock client that returns different responses based on the request
	responseCounter := 0
	mockClient := &MockHTTPClient{
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(bytes.NewReader([]byte(`[
				{"tag_name": "v0.1.0"},
				{"tag_name": "v0.2.0"}
			]`))),
		},
	}

	// Set up the DoFunc to return different responses
	mockClient.DoFunc = func(req *http.Request) (*http.Response, error) {
		if responseCounter == 0 {
			responseCounter++
			return mockClient.Response, nil
		}

		// For the second request (eif-info.txt)
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
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(eifInfoJSON)),
		}, nil
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
			expectedError: "",
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
