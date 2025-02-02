// Copyright (c) 2025 Edoardo Spadolini
// SPDX-License-Identifier: MIT

package rolesanywhere

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type CreateSessionParams struct {
	RoundTripper http.RoundTripper

	Certificate     *x509.Certificate
	HashAndSignFunc func(string) ([]byte, error)

	Region string

	TrustAnchorARN string
	ProfileARN     string
	RoleARN        string

	Duration time.Duration
}

func CreateSession(ctx context.Context, params CreateSessionParams) (Credentials, error) {
	var signatureAlgorithm string
	switch p := params.Certificate.PublicKeyAlgorithm; p {
	case x509.ECDSA:
		signatureAlgorithm = "AWS4-X509-ECDSA-SHA256"
	case x509.RSA:
		signatureAlgorithm = "AWS4-X509-RSA-SHA256"
	default:
		return Credentials{}, fmt.Errorf("unsupported public key algorithm %s", p)
	}

	reqBody, err := json.Marshal(createSessionInput{
		TrustAnchorARN:  params.TrustAnchorARN,
		ProfileARN:      params.ProfileARN,
		RoleARN:         params.RoleARN,
		DurationSeconds: int(params.Duration / time.Second),
	})
	if err != nil {
		return Credentials{}, err
	}

	reqURL := &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("rolesanywhere.%v.amazonaws.com", params.Region),
		Path:   "/sessions",
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		return Credentials{}, err
	}

	const signedHeaders = "content-type;host;x-amz-date;x-amz-x509"

	req.Header.Set("Content-Type", "application/json")

	now := time.Now().UTC().Round(time.Second)
	xAmzDate := now.Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", xAmzDate)

	xAmzX509 := base64.StdEncoding.EncodeToString(params.Certificate.Raw)
	req.Header.Set("X-Amz-X509", xAmzX509)

	canonicalRequest := sha256.New()
	fmt.Fprintf(canonicalRequest,
		"POST\n/sessions\n\ncontent-type:application/json\nhost:%v\nx-amz-date:%v\nx-amz-x509:%v\n\n%v\n%x",
		reqURL.Host,
		xAmzDate,
		xAmzX509,
		signedHeaders,
		sha256.Sum256(reqBody),
	)

	scope := fmt.Sprintf("%v/%v/rolesanywhere/aws4_request", now.Format("20060102"), params.Region)

	stringToSign := fmt.Sprintf(
		"%v\n%v\n%v\n%x",
		signatureAlgorithm,
		xAmzDate,
		scope,
		canonicalRequest.Sum(nil),
	)

	signature, err := params.HashAndSignFunc(stringToSign)
	if err != nil {
		return Credentials{}, fmt.Errorf("signing request: %w", err)
	}

	credentialID := params.Certificate.SerialNumber.String()
	req.Header.Set("Authorization", fmt.Sprintf(
		"%v Credential=%v/%v, SignedHeaders=%v, Signature=%x",
		signatureAlgorithm,
		credentialID,
		scope,
		signedHeaders,
		signature,
	))

	resp, err := params.RoundTripper.RoundTrip(req)
	if err != nil {
		return Credentials{}, fmt.Errorf("writing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		errBody, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, 16*1024))
		if err != nil {
			return Credentials{}, fmt.Errorf("reading error response with status %q: %w", resp.Status, err)
		}
		return Credentials{}, fmt.Errorf("error response with status %q: %q", resp.Status, errBody)
	}

	respBody, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, 128*1024))
	if err != nil {
		return Credentials{}, fmt.Errorf("reading response: %w", err)
	}

	var out createSessionOutput
	if err := json.Unmarshal(respBody, &out); err != nil {
		return Credentials{}, fmt.Errorf("parsing response: %w", err)
	}

	if le := len(out.CredentialSet); le != 1 {
		return Credentials{}, fmt.Errorf("unexpected credentialSet size: got %v, expected 1", le)
	}

	outCred := out.CredentialSet[0].Credentials

	expiration, err := time.Parse(time.RFC3339, outCred.Expiration)
	if err != nil {
		return Credentials{}, fmt.Errorf("parsing credentials expiration: %w", err)
	}

	return Credentials{
		AccessKeyID:     outCred.AccessKeyId,
		SecretAccessKey: outCred.SecretAccessKey,
		SessionToken:    outCred.SessionToken,
		Expiration:      expiration,
	}, nil
}

type createSessionInput struct {
	TrustAnchorARN  string `json:"trustAnchorArn"`
	ProfileARN      string `json:"profileArn"`
	RoleARN         string `json:"roleArn"`
	DurationSeconds int    `json:"durationSeconds"`
}

type createSessionOutput struct {
	CredentialSet []struct {
		Credentials struct {
			AccessKeyId     string
			SecretAccessKey string
			SessionToken    string
			Expiration      string
		}
	}
}

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}
