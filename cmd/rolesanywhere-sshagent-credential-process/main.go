// Copyright (c) 2025 Edoardo Spadolini
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/espadolini/rolesanywhere/rolesanywhere"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	defer context.AfterFunc(ctx, cancel)()

	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	var region, trustAnchorARN, profileARN, roleARN string
	var duration time.Duration
	flag.StringVar(&region, "region", "", "AWS region (required)")
	flag.StringVar(&trustAnchorARN, "trust-anchor-arn", "", "trust anchor ARN (required)")
	flag.StringVar(&profileARN, "profile-arn", "", "profile ARN (required)")
	flag.StringVar(&roleARN, "role-arn", "", "role ARN (required)")
	flag.DurationVar(&duration, "duration", time.Hour, "credential duration")

	var certificatePath, agentPath string
	flag.StringVar(&certificatePath, "certificate", "", "path to certificate in DER format (required)")
	flag.StringVar(&agentPath, "agent", "", "path to agent socket (required)")

	flag.Parse()

	certDer, err := os.ReadFile(certificatePath)
	if err != nil {
		return fmt.Errorf("reading certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}
	pubKey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	agConn, err := new(net.Dialer).DialContext(ctx, "unix", agentPath)
	if err != nil {
		return fmt.Errorf("connecting to agent: %w", err)
	}
	defer agConn.Close()
	defer context.AfterFunc(ctx, func() { _ = agConn.Close() })()

	ag := agent.NewClient(agConn)

	creds, err := rolesanywhere.CreateSession(ctx, rolesanywhere.CreateSessionParams{
		RoundTripper: http.DefaultTransport,

		Certificate: cert,
		HashAndSignFunc: func(s string) ([]byte, error) {
			var flags agent.SignatureFlags
			if cert.PublicKeyAlgorithm == x509.RSA {
				// for rsa we have to ask for SHA256 because the default uses
				// SHA1 for hashing, but the format of the returned signature
				// should already be PKCS #1 v1.5 (untested)
				flags |= agent.SignatureFlagRsaSha256
			}
			sshSig, err := ag.SignWithFlags(pubKey, []byte(s), flags)
			if err != nil {
				return nil, fmt.Errorf("signing request: %w", err)
			}
			signature := sshSig.Blob
			if cert.PublicKeyAlgorithm == x509.ECDSA {
				// for ecdsa we have to repackage the SSH signature into an
				// ASN.1 sequence
				var inner struct {
					R, S *big.Int
				}
				if err := ssh.Unmarshal(sshSig.Blob, &inner); err != nil {
					return nil, fmt.Errorf("parsing signature: %w", err)
				}
				b, err := asn1.Marshal([]*big.Int{inner.R, inner.S})
				if err != nil {
					return nil, fmt.Errorf("marshaling signature: %w", err)
				}
				signature = b
			}
			return signature, nil
		},

		Region: region,

		TrustAnchorARN: trustAnchorARN,
		ProfileARN:     profileARN,
		RoleARN:        roleARN,

		Duration: duration,
	})
	if err != nil {
		return fmt.Errorf("obtaining credentials: %w", err)
	}

	out := credentialProcessOutput{
		Version:         1,
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expiration.Format(time.RFC3339),
	}

	j, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshaling output: %w", err)
	}

	_, _ = os.Stdout.Write(j)
	return nil
}

type credentialProcessOutput struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}
