// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/vbhledger-blockchain/library/gm/sm/sm2"
	"github.com/vbhledger-blockchain/library/gm/sm/x509"
	"hash"
	"io"
)

// pickSignatureAlgorithm selects a signature algorithm that is compatible with
// the given public key and the list of algorithms from the peer and this side.
// The lists of signature algorithms (peerSigAlgs and ourSigAlgs) are ignored
// for tlsVersion < VersionTLS12.
//
// The returned SignatureScheme codepoint is only meaningful for TLS 1.2,
// previous TLS versions have a fixed hash function.
func pickSignatureAlgorithm(pubkey crypto.PublicKey, peerSigAlgs, ourSigAlgs []SignatureScheme, tlsVersion uint16) (sigAlg SignatureScheme, sigType uint8, hashFunc x509.Hash, err error) {
	if tlsVersion < VersionTLS12 || len(peerSigAlgs) == 0 {
		// For TLS 1.1 and before, the signature algorithm could not be
		// negotiated and the hash is fixed based on the signature type. For TLS
		// 1.2, if the client didn't send signature_algorithms extension then we
		// can assume that it supports SHA1. See RFC 5246, Section 7.4.1.4.1.
		switch pubkey.(type) {
		case *rsa.PublicKey:
			if tlsVersion < VersionTLS12 {
				return 0, signaturePKCS1v15, x509.MD5SHA1, nil
			} else {
				return PKCS1WithSHA1, signaturePKCS1v15, x509.SHA1, nil
			}
		case *ecdsa.PublicKey:
			return ECDSAWithSHA1, signatureECDSA, x509.SHA1, nil
		case *sm2.PublicKey:
			return SM2WithSM3, SignatureSM2, x509.SM3, nil
		default:
			return 0, 0, 0, fmt.Errorf("tls: unsupported public key: %T", pubkey)
		}
	}
	for _, sigAlg := range peerSigAlgs {
		if !isSupportedSignatureAlgorithm(sigAlg, ourSigAlgs) {
			continue
		}
		hashAlg, err := hashFromSignatureScheme(sigAlg)
		if err != nil {
			panic("tls: supported signature algorithm has an unknown hash function")
		}
		sigType := signatureFromSignatureScheme(sigAlg)
		switch pubkey.(type) {
		case *rsa.PublicKey:
			if sigType == signaturePKCS1v15 || sigType == signatureRSAPSS {
				return sigAlg, sigType, hashAlg, nil
			}
		case *ecdsa.PublicKey:
			if sigType == signatureECDSA {
				return sigAlg, sigType, hashAlg, nil
			}
		case *sm2.PublicKey:
			if sigType == SignatureSM2 {
				return sigAlg, sigType, hashAlg, nil
			}
		default:
			return 0, 0, 0, fmt.Errorf("tls: unsupported public key: %T", pubkey)
		}
	}
	return 0, 0, 0, errors.New("tls: peer doesn't support any common signature algorithms")
}

//  验证握手签名
func verifyHandshakeSignature(sigType uint8, pubkey crypto.PublicKey, hashFunc x509.Hash, digest, sig []byte) error {
	switch sigType {
	case signatureECDSA:
		pubKey, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("tls: ECDSA signing requires a ECDSA public key")
		}
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("tls: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pubKey, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("tls: ECDSA verification failure")
		}
	case signaturePKCS1v15:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return errors.New("tls: RSA signing requires a RSA public key")
		}
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.Hash(hashFunc), digest, sig); err != nil {
			return err
		}
	case signatureRSAPSS:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return errors.New("tls: RSA signing requires a RSA public key")
		}
		signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		if err := rsa.VerifyPSS(pubKey, crypto.Hash(hashFunc), digest, sig, signOpts); err != nil {
			return err
		}
	case SignatureSM2:
		sm2Sig := new(sm2.Sm2Signature)
		if rest, err := asn1.Unmarshal(sig, sm2Sig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("x509: trailing data after SM2 signature")
		}
		if sm2Sig.R.Sign() <= 0 || sm2Sig.S.Sign() <= 0 {
			return errors.New("x509: SM2 signature contained zero or negative values")
		}
		pubkey, ok := pubkey.(*sm2.PublicKey)
		if !ok {
			return errors.New("tls: sm2 signing requires a sm2 public key")
		}
		if !sm2.Sm2Verify(pubkey, digest, nil, sm2Sig.R, sm2Sig.S) {
			return errors.New("x509: SM2 verification failure")
		}
		return nil
	default:
		return errors.New("tls: unknown signature algorithm")
	}
	return nil
}

const (
	serverSignatureContext = "TLS 1.3, server CertificateVerify\x00"
	clientSignatureContext = "TLS 1.3, client CertificateVerify\x00"
)

var signaturePadding = []byte{
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
}

// writeSignedMessage writes the content to be signed by certificate keys in TLS
// 1.3 to sigHash. See RFC 8446, Section 4.4.3.
//写签名消息
func writeSignedMessage(sigHash io.Writer, context string, transcript hash.Hash) {
	sigHash.Write(signaturePadding)
	io.WriteString(sigHash, context)
	sigHash.Write(transcript.Sum(nil))
}

// signatureSchemesForCertificate returns the list of supported SignatureSchemes
// for a given certificate, based on the public key and the protocol version. It
// does not support the crypto.Decrypter interface, so shouldn't be used on the
// server side in TLS 1.2 and earlier.
//签名证书方案
func signatureSchemesForCertificate(version uint16, cert *Certificate) []SignatureScheme {
	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil
	}

	switch pub := priv.Public().(type) {
	case *ecdsa.PublicKey:
		if version != VersionTLS13 {
			// In TLS 1.2 and earlier, ECDSA algorithms are not
			// constrained to a single curve.
			return []SignatureScheme{
				ECDSAWithP256AndSHA256,
				ECDSAWithP384AndSHA384,
				ECDSAWithP521AndSHA512,
				ECDSAWithSHA1,
			}
		}
		switch pub.Curve {
		case elliptic.P256():
			return []SignatureScheme{ECDSAWithP256AndSHA256}
		case elliptic.P384():
			return []SignatureScheme{ECDSAWithP384AndSHA384}
		case elliptic.P521():
			return []SignatureScheme{ECDSAWithP521AndSHA512}
		default:
			return nil
		}
	case *rsa.PublicKey:
		if version != VersionTLS13 {
			return []SignatureScheme{
				PSSWithSHA256,
				PSSWithSHA384,
				PSSWithSHA512,
				PKCS1WithSHA256,
				PKCS1WithSHA384,
				PKCS1WithSHA512,
				PKCS1WithSHA1,
			}
		}
		// RSA keys with RSA-PSS OID are not supported by crypto/x509.
		return []SignatureScheme{
			PSSWithSHA256,
			PSSWithSHA384,
			PSSWithSHA512,
		}
	case *sm2.PublicKey:
		return []SignatureScheme{SM2WithSM3}
	default:
		return nil
	}
}

// unsupportedCertificateError returns a helpful error for certificates with
// an unsupported private key.
// 不支持的证书错误
func unsupportedCertificateError(cert *Certificate) error {
	switch cert.PrivateKey.(type) {
	case rsa.PrivateKey, ecdsa.PrivateKey, sm2.PrivateKey:
		return fmt.Errorf("tls: unsupported certificate: private key is %T, expected *%T",
			cert.PrivateKey, cert.PrivateKey)
	}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("tls: certificate private key (%T) does not implement crypto.Signer",
			cert.PrivateKey)
	}

	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
		case elliptic.P384():
		case elliptic.P521():
		default:
			return fmt.Errorf("tls: unsupported certificate curve (%s)", pub.Curve.Params().Name)
		}
	case *rsa.PublicKey:
	case *sm2.PublicKey:
		if pub.Curve != sm2.P256Sm2() {
			return fmt.Errorf("tls: unsupported sm2 certificate curve (%s)", pub.Curve.Params().Name)
		}
	default:
		return fmt.Errorf("tls: unsupported certificate key (%T)", pub)
	}

	return fmt.Errorf("tls: internal error: unsupported key (%T)", cert.PrivateKey)
}

// go tool pprof -pdf crypto_test.go cpu.out > cpu.pdf
