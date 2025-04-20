package lib

import (
	"context"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/mdlayher/vsock"
	nitro "github.com/veracruz-project/go-nitro-enclave-attestation-document"
)

// Base32Encoder is the standard base32 encoder with no padding, used for encoding/decoding attestation data
var Base32Encoder = base32.StdEncoding.WithPadding(base32.NoPadding)

// S3BucketName is the name of the AWS S3 bucket to use
const S3BucketName = "teels-attestations"

type AttestationReport struct {
	UnverifiedAttestedData []byte `json:"unverified_attested_data"`
	AwsNitroAttestation    []byte `json:"aws_nitro_attestation"`
}

// FileSystem interface for mocking file operations
type FileSystem interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
}

// getValidatedAttestationDoc validates and returns the attestation document from the base64 encoded attestation
func GetValidatedAttestationDoc(base64EncodedAttestation string, fs FileSystem) (*nitro.AttestationDocument, error) {
	if base64EncodedAttestation == "" {
		return nil, fmt.Errorf("no AWS Nitro attestation data found")
	}

	attestationBytes, err := base64.StdEncoding.DecodeString(base64EncodedAttestation)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AWS Nitro attestation: %w", err)
	}

	path := "cert_verifier/aws_nitro_root.pem"
	if os.Getenv("AWS_NITRO") == "true" {
		path = "/app/aws_nitro_root.pem"
	}
	rootCertPEM, err := fs.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read AWS Nitro root certificate: %w", err)
	}

	block, _ := pem.Decode(rootCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate: %w", err)
	}

	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		return nil, fmt.Errorf("failed to verify root certificate signature: %w", err)
	}

	doc, err := nitro.AuthenticateDocument(attestationBytes, *rootCert, true)
	if err != nil {
		return nil, fmt.Errorf("failed to validate AWS Nitro attestation: %w", err)
	}

	return doc, nil
}

// PublishToS3 publishes content to an AWS S3 bucket
func PublishToS3(ctx context.Context, httpClient *http.Client, content, filename string) error {
	type AwsCreds struct {
		AWSAccessKeyID     string `json:"AWS_ACCESS_KEY_ID"`
		AWSSecretAccessKey string `json:"AWS_SECRET_ACCESS_KEY"`
		AWSSessionToken    string `json:"AWS_SESSION_TOKEN"`
		AWSRegion          string `json:"AWS_REGION"`
	}

	log.Printf("[DEBUG] Starting vsock listener on port 1337")
	listener, err := vsock.Listen(1337, nil)
	if err != nil {
		return fmt.Errorf("failed to create vsock listener: %w", err)
	}
	defer listener.Close()

	log.Printf("[DEBUG] Waiting for vsock connection...")
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept vsock connection: %w", err)
	}
	defer conn.Close()

	// Read the raw JSON first
	rawJSON, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("failed to read raw JSON: %w", err)
	}

	var creds AwsCreds
	if err := json.Unmarshal(rawJSON, &creds); err != nil {
		return fmt.Errorf("failed to decode credentials: %w", err)
	}

	if creds.AWSAccessKeyID == "" || creds.AWSSecretAccessKey == "" {
		return fmt.Errorf("required AWS credentials are empty")
	}

	// Load AWS config using received credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(creds.AWSRegion),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			creds.AWSAccessKeyID, creds.AWSSecretAccessKey, creds.AWSSessionToken,
		)),
		config.WithHTTPClient(httpClient),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client
	client := s3.NewFromConfig(cfg)
	log.Printf("[DEBUG] Attempting to upload to S3 bucket %s with key %s", S3BucketName, filename)

	// Upload content to S3
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:  aws.String(S3BucketName),
		Key:     aws.String(filename),
		Body:    strings.NewReader(content),
		Expires: aws.Time(time.Now().AddDate(1, 0, 0)), // Add 1 year expiration
	})
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	log.Printf("[DEBUG] Successfully uploaded to S3")
	return nil
}
