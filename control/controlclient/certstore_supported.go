// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows,cgo

// darwin,cgo is also supported by certstore but machineCertificateSubject will
// need to be loaded by a different mechanism, so this is not currently enabled
// on darwin.

package controlclient

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/github/certstore"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
	"tailscale.com/util/winutil"
)

// MachineCertificateSubject is the exact name of a Subject that needs to be
// present in an identity's certificate chain to sign a RegisterRequest,
// formatted as per pkix.Name.String(). The Subject may be that of the identity
// itself, an intermediate CA or the root CA.
//
// If MachineCertificateSubject is "" then no lookup will occur and
// each RegisterRequest will be unsigned.
//
// Example: "CN=Tailscale Inc Test Root CA,OU=Tailscale Inc Test Certificate Authority,O=Tailscale Inc,ST=ON,C=CA"
var machineCertificateSubject string = winutil.GetRegString("MachineCertificateSubject", "")

// findIdentity locates an identity from the Windows or Darwin certificate
// store. It returns the first certificate with a matching Subject anywhere in
// its certificate chain, so it is possible to search for the leaf certificate,
// intermediate CA or root CA.
func findIdentity(subject string, st certstore.Store) (certstore.Identity, error) {
	ids, err := st.Identities()
	if err != nil {
		return nil, err
	}

	var selected certstore.Identity

	for i, id := range ids {
		chain, err := id.CertificateChain()
		if err != nil {
			log.Printf("unable to build x509 cert %v: %v", i, err)
			continue
		}

		if chain[0].PublicKeyAlgorithm != x509.RSA {
			log.Printf("unsuitable cert %v: not RSA", i)
			continue
		}

		for _, c := range chain {
			if c.Subject.String() == subject {
				log.Printf("Selected subject: %q (for identity %q)", c.Subject, chain[0].Subject)
				selected = id
				break
			}
			log.Printf("Rejected subject: %q", c.Subject)
		}
	}

	for _, id := range ids {
		if id != selected {
			id.Close()
		}
	}

	return selected, nil
}

// signRegisterRequest looks for a suitable machine identity from the local
// system certificate store, and if one is found, signs the RegisterRequest
// using that identity's public key. In addition to the signature, the full
// certificate chain is included so that the control server can validate the
// certificate from a copy of the root CA's certificate.
func signRegisterRequest(req *tailcfg.RegisterRequest, serverURL string, serverPubKey, machinePubKey wgkey.Key) (e error) {
	defer func() {
		if e != nil {
			e = fmt.Errorf("signRegisterRequest: %w", e)
		}
	}()

	if machineCertificateSubject == "" {
		return errCertificateNotConfigured
	}

	st, err := certstore.Open(certstore.System)
	if err != nil {
		log.Printf("unable to open cert store for register request: %v", err)
		return err
	}
	defer st.Close()

	id, err := findIdentity(machineCertificateSubject, st)
	if err != nil || id == nil {
		log.Printf("unable to find identity for register request: %v", err)
		return err
	}
	defer id.Close()

	signer, err := id.Signer()
	if err != nil {
		log.Printf("unable to set up signer for register request: %v", err)
		return err
	}

	chain, err := id.CertificateChain()
	if err != nil {
		log.Printf("unable to set up cert chain: %v", err)
		return err
	}
	cl := 0
	for _, c := range chain {
		cl += len(c.Raw)
	}
	req.DeviceCert = make([]byte, 0, cl)
	for _, c := range chain {
		req.DeviceCert = append(req.DeviceCert, c.Raw...)
	}

	hf := crypto.SHA256
	h := hf.New()
	if err := req.WritePlaintextForSigning(h, serverURL, serverPubKey, machinePubKey); err != nil {
		return err
	}

	req.Signature, err = signer.Sign(nil, h.Sum(nil), &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hf,
	})
	if err != nil {
		log.Printf("unable to sign request: %v", err)
		return err
	}
	req.SignatureAlgorithm = x509.SHA256WithRSAPSS

	return nil
}
