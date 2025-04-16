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

// S3BucketName is the name of the AWS S3 bucket to use
const S3BucketName = "teels-attestations"

type AttestationReport struct {
	UnverifiedAttestedData []byte `json:"unverified_attested_data"`
	AwsNitroAttestation    []byte `json:"aws_nitro_attestation"`
}

// PublishToS3 publishes content to an AWS S3 bucket
func PublishToS3(ctx context.Context, content string, filename string) error {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	region := os.Getenv("AWS_REGION")

	// Load AWS config
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return err
	}

	// Create S3 client
	client := s3.NewFromConfig(cfg)

	// Upload content to S3
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(S3BucketName),
		Key:    aws.String(filename),
		Body:   io.NopCloser(strings.NewReader(content)),
	})

	return err
}
