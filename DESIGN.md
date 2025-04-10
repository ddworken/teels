Set up:
1. Create *.verified.example.com pointing to the TEE

From inside a TEE:
1. Generate a TLS private/public key pair 
2. Calculate pubH = hash(pubK)
3. Retrieve Att = attest(pubH)
4. Calculate AttH = hash(att)
5. Use LetsEncrypt to create cert(verified.example.com, $AttH.verified.example.com). Can use HTTP challenge for this!

CT Verification:
1. Watch CT logs for verified.example.com
2. Check that every cert also has $AttH.verified.example.com in it 
3. Use $AttH to retrieve the attestation from content-addressable storage 
4. Get $Attestation.Data to get pubH
5. Assert that pubH matches cert 
6. Assert that there are no other certs that match (i.e. no *.example.com or *.verified.example.com)

Client verification (removes CT dependency):
1. Hook into cert validation inside of a client (e.g. in firefox extension or in a non-browser client)
2. Perform above steps 

Ideal API:
* Golang binary. Run it at startup of a TEE and it provisions a cert before the main program is started. Main program can then just run with the cert.

----

Write a go program that is a standalone binary that follows this example code from the acme-go library to create a TLS cert, but it also:

```
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {

	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: "you@yours.com",
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = "http://192.168.99.100:4000/directory"
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// We specify an HTTP port of 5002 and an TLS port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "5002"))
	if err != nil {
		log.Fatal(err)
	}
	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "5001"))
	if err != nil {
		log.Fatal(err)
	}

	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{"mydomain.com"},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("%#v\n", certificates)

	// ... all done.
}
```

1. Defines a function `attest(data []byte) []byte` that I will define later. This function will be defined using TEE-specific functionality to create an attestation bound to the given data.
2. Calculates the public key (in x509 format)
3. sha256 Hashes the public key and passes it to attest to get an attestation report 
4. Calculates the sha256 hash of the attestation report 
5. Encodes the hash using a url-safe base32 into a subdomain of `$hash.verified-dev.daviddworken.com`. Make sure to disable padding of the base32 value.
6. Uses lets encrypt to provision a cert for the above subdomain and `verified-dev.daviddworken.com`. Pull the lets encrypt email address from an environment variable named `LETS_ENCRYPT_EMAIL_ADDRESS`.
7. Writes the public key, private key, cert, and attest values to files to be used by another later program. Use x509 format for all of this. 

----

Write a go function that takes in a TLS cert in x509 format and applies a series of validations. If any of these validations fail, the overall program should fail. The validations are:

1. Check that it is for exactly two hostnames: `verified-dev.daviddworken.com` and some subdomain of `verified-dev.daviddworken.com` (i.e. `xxx.verified-dev.daviddworken.com`)
2. Parses out the subdomain of `verified-dev.daviddworken.com` (i.e. `xxx.verified-dev.daviddworken.com` --> `xxx`) and decodes it using base32 
3. Calls `getAttestation(hash []byte) []byte`, a stub function that I'll implement myself to get an attestation from the hash pulled out of the URL 
4. Uses https://github.com/google/go-sev-guest to parse and verify the attestation
5. Extracts the REPORT_DATA field from the attestation
6. Calculates the sha256 hash of the public key (in x509 format) in the cert and asserts that it matches the data in the REPORT_DATA field 

--- 

SEV-SNP spec: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf

GCP attestations: Unclear if it easily gives me what I want 
* https://cloud.google.com/confidential-computing/confidential-vm/docs/attestation
* https://cloud.google.com/confidential-computing/confidential-vm/docs/token-claims
 
 ---

 ```
aws ec2 run-instances \
--image-id ami-0515da4bec0819859 \
--count 1 \
--instance-type c7g.large \
--region ap-south-1 \
--key-name mac \
--enclave-options 'Enabled=true'

ssh ec2-user@ec2-65-2-80-196.ap-south-1.compute.amazonaws.com

 ```