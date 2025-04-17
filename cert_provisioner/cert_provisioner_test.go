package main

import (
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
