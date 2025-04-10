package lib

import (
	"context"
	"encoding/base32"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Base32Encoder is the standard base32 encoder with no padding, used for encoding/decoding attestation data
var Base32Encoder = base32.StdEncoding.WithPadding(base32.NoPadding)

// GCSBucketName is the name of the Google Cloud Storage bucket to use
const GCSBucketName = "teels-attestations"

// FakeAttestation represents a simulated attestation report
type FakeAttestation struct {
	AttestedData []byte `json:"attested_data"`
}

// PublishToGCS publishes content to a GCS bucket using S3-compatible APIs
func PublishToGCS(ctx context.Context, content string, filename string) error {
	accessKey := os.Getenv("GCS_ACCESS_KEY_ID")
	secretKey := os.Getenv("GCS_SECRET_ACCESS_KEY")
	endpoint := "https://storage.googleapis.com"

	// Create custom resolver for GCS endpoint
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL:           endpoint,
			SigningRegion: "auto",
		}, nil
	})

	// Load AWS config with custom endpoint resolver
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return err
	}

	// Create S3 client
	client := s3.NewFromConfig(cfg)

	// Upload content to GCS
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(GCSBucketName),
		Key:    aws.String(filename),
		Body:   io.NopCloser(strings.NewReader(content)),
	})

	return err
}
