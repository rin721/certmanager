// Package parser 使用标准库解析并校验证书，不承担任何签名逻辑。
package parser

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Metadata struct {
	Subject           pkix.Name
	Issuer            pkix.Name
	SerialNumber      string
	DNSNames          []string
	NotBefore         time.Time
	NotAfter          time.Time
	FingerprintSHA256 string
	KeyAlgorithm      string
}

func ParseCertificate(certificatePEM []byte) (*x509.Certificate, Metadata, error) {
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, Metadata{}, errors.New("未找到有效的 CERTIFICATE PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("解析证书: %w", err)
	}
	digest := sha256.Sum256(certificate.Raw)
	metadata := Metadata{
		Subject:           certificate.Subject,
		Issuer:            certificate.Issuer,
		SerialNumber:      strings.ToUpper(certificate.SerialNumber.Text(16)),
		DNSNames:          append([]string(nil), certificate.DNSNames...),
		NotBefore:         certificate.NotBefore,
		NotAfter:          certificate.NotAfter,
		FingerprintSHA256: strings.ToUpper(hex.EncodeToString(digest[:])),
		KeyAlgorithm:      publicKeyAlgorithm(certificate.PublicKey),
	}
	return certificate, metadata, nil
}

func ValidateCertificateAndKey(certificatePEM, privateKeyPEM []byte, expectedDomains []string, now time.Time) (Metadata, error) {
	certificate, metadata, err := ParseCertificate(certificatePEM)
	if err != nil {
		return Metadata{}, err
	}
	if now.Before(certificate.NotBefore.Add(-5*time.Minute)) || !now.Before(certificate.NotAfter) {
		return Metadata{}, errors.New("证书当前不在有效期内")
	}
	// CheckSignatureFrom 还会执行 CA 约束检查，不能用于验证合法的自签名叶证书。
	// 这里仅验证证书的 TBS 数据确实由其自身公钥签名。
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		return Metadata{}, fmt.Errorf("自签名证书签名校验失败: %w", err)
	}
	if !sameStrings(certificate.DNSNames, expectedDomains) {
		return Metadata{}, fmt.Errorf("证书 SAN 与请求不一致: got=%v want=%v", certificate.DNSNames, expectedDomains)
	}
	if err := ValidateKeyMatches(certificate, privateKeyPEM); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func ValidateKeyMatches(certificate *x509.Certificate, privateKeyPEM []byte) error {
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return err
	}
	publicKey, ok := privateKey.(crypto.Signer)
	if !ok {
		return errors.New("私钥不支持签名")
	}
	want, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return err
	}
	got, err := x509.MarshalPKIXPublicKey(publicKey.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("证书与私钥不匹配")
	}
	return nil
}

func parsePrivateKey(value []byte) (any, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, errors.New("未找到有效的私钥 PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("不支持的私钥格式")
}

func publicKeyAlgorithm(key any) string {
	switch value := key.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA-" + value.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", value.N.BitLen())
	default:
		return "UNKNOWN"
	}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]int, len(left))
	for _, value := range left {
		seen[value]++
	}
	for _, value := range right {
		seen[value]--
	}
	for _, count := range seen {
		if count != 0 {
			return false
		}
	}
	return true
}
