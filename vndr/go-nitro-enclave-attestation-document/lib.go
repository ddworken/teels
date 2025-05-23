//! A go module for authenticating and parsing AWS nitro enclave attestation documents
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

package nitro_eclave_attestation_document

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	zcrypto_x509 "github.com/zmap/zcrypto/ct/x509"
)

type AttestationDocument struct {
	ModuleId    string
	TimeStamp   uint64
	Digest      string
	PCRs        map[int32][]byte
	Certificate []byte
	CABundle    [][]byte
	PublicKey   []byte
	User_Data   []byte // This non-standard format for this variable is required. Don't change it
	Nonce       []byte
}

// / Authenticate an AWS Nitro Enclave attestation document with the provided root certificate.
// / If authentication passes, return the generated AttestationDocument representing the fields
// / from the provided CBOR data
// / data - the document data to be authenticated
// / root_certificate - the root certificate to be used to authenticate the document
// / add_prefix - The AWS implementation of COSE (and the Rust implementation) excludes a prefix
// /  to the document that the golang implementation expects. Setting this parameter to true will
// /  assume the prefix is not there and adds it. Otherwise, the `data` input is left as-is.
func AuthenticateDocument(data []byte, root_certificate interface{}, add_prefix bool) (*AttestationDocument, error) {
	// Following the steps here: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
	// Step 1. Decode the CBOR object and map it to a COSE_Sign1 structure
	var msg cose.Sign1Message
	// The go-cose library wants a special prefix on the data that I'm not seeing from AWS (and that the rust implementation
	// of cose is not expecting. Adding it to make it happy)
	if add_prefix {
		data = append([]byte{0xd2}, data...)
	}
	err := msg.UnmarshalCBOR(data)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument::UnmarshalCBOR failed:%v", err)
	}

	// Step 2. Extract the attestation document from the COSE_Sign1 structure
	document, err := parsePayload(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument:parsePayload failed:%v", err)
	}
	// Step 3. Verify the certificate's chain
	intermediates_pool := zcrypto_x509.NewCertPool()
	for _, this_cert_der := range document.CABundle {
		this_cert, err := zcrypto_x509.ParseCertificate(this_cert_der)
		if err != nil {
			return nil, fmt.Errorf("AuthenticateDocument:ParseCertificate failed:%v", err)
		}
		intermediates_pool.AddCert(this_cert)
	}
	root_pool := zcrypto_x509.NewCertPool()

	// Convert the root certificate to zcrypto's x509.Certificate if needed
	var zcryptoCert *zcrypto_x509.Certificate
	switch cert := root_certificate.(type) {
	case *zcrypto_x509.Certificate:
		zcryptoCert = cert
	case zcrypto_x509.Certificate:
		zcryptoCert = &cert
	case *x509.Certificate:
		// Convert standard library certificate to zcrypto certificate
		zcryptoCert, err = zcrypto_x509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, fmt.Errorf("AuthenticateDocument:Failed to convert root certificate:%v", err)
		}
	case x509.Certificate:
		// Convert standard library certificate to zcrypto certificate
		zcryptoCert, err = zcrypto_x509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, fmt.Errorf("AuthenticateDocument:Failed to convert root certificate:%v", err)
		}
	default:
		return nil, fmt.Errorf("AuthenticateDocument:Invalid root certificate type: got %T, expected x509.Certificate or *x509.Certificate", root_certificate)
	}
	root_pool.AddCert(zcryptoCert)

	end_user_cert, err := zcrypto_x509.ParseCertificate(document.Certificate)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument:ParseCertificate failed:%v", err)
	}
	cert_verify_options := zcrypto_x509.VerifyOptions{
		Intermediates: intermediates_pool,
		Roots:         root_pool,
		KeyUsages:     []zcrypto_x509.ExtKeyUsage{zcrypto_x509.ExtKeyUsageAny},
		// Ignore date constraints. Nitro attestations are usually only valid for a short period of time, but
		// we need to be able to verify them for the lifetime of a TLS cert.
		// TODO: If this code is being productionized, this should be tightened up to e.g. just disable time-based
		// checks for the lifetime of the cert (but still reject any attestations that are outside the cert lifetime).
		DisableTimeChecks: true,
	}
	_, err = end_user_cert.Verify(cert_verify_options)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument: Failed to verify certificate chain:%v", err)
	}
	// Step 4. Ensure the attestation document is properly signed
	verifier, err := cose.NewVerifier(cose.AlgorithmES384, end_user_cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("NewVerifier failed:%v\n", err)
	}
	err = msg.Verify(nil, verifier)
	if err != nil {
		return nil, fmt.Errorf("AuthenticateDocument::Verify failed:%v", err)
	}

	// All is good, return the document
	return document, nil
}

// / Generate CBOR for a fake AWS Nitro Enclave attestation document, signed by the provided key, with the `signingCertDer` embedded in the `Certificate` field and the
// / `caBundle` embedded as the `CABundle` field.
// / This interface is useful for testing. Beyond that, there should be no reason for you to generate your own attestation document
func GenerateDocument(PCRs map[int32][]byte, userData []byte, nonce []byte, signingCertDer []byte, caBundle [][]byte, signingKey *ecdsa.PrivateKey) ([]byte, error) {
	document := AttestationDocument{
		ModuleId:    "MyId",
		TimeStamp:   uint64(time.Now().UnixMilli()),
		Digest:      "SHA384",
		PCRs:        PCRs,
		Certificate: signingCertDer,
		CABundle:    caBundle,
		PublicKey:   []byte{},
		User_Data:   userData,
		Nonce:       nonce,
	}
	payload, err := cbor.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("cbor Marshal of document failed:%v", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	signer, err := cose.NewSigner(cose.AlgorithmES384, signingKey)
	if err := msg.Sign(rand.Reader, []byte{}, signer); err != nil {
		return nil, fmt.Errorf("Failed to sign:%v\n", err)
	}

	messageCbor, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal CBOR:%v\n", err)
	}
	return messageCbor, nil
}

func parsePayload(payload []byte) (*AttestationDocument, error) {
	document := new(AttestationDocument)
	err := cbor.Unmarshal(payload, document)
	if err != nil {
		return nil, fmt.Errorf("parse_payload: cbor.Unmarshal failed:%v\n", err)
	}
	return document, nil
}
