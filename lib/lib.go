package lib

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/mdlayher/vsock"
)

// Base32Encoder is the standard base32 encoder with no padding, used for encoding/decoding attestation data
var Base32Encoder = base32.StdEncoding.WithPadding(base32.NoPadding)

// S3BucketName is the name of the AWS S3 bucket to use
const S3BucketName = "teels-attestations"

type AttestationReport struct {
	UnverifiedAttestedData []byte `json:"unverified_attested_data"`
	AwsNitroAttestation    []byte `json:"aws_nitro_attestation"`
}

// PublishToS3 publishes content to an AWS S3 bucket
func PublishToS3(ctx context.Context, httpClient *http.Client, content string, filename string) error {
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
