package certificate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	cache  sync.Map
}

func LoadOrCreate(certFile, keyFile string) (*Manager, error) {
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	if certErr == nil && keyErr == nil {
		return Load(certFile, keyFile)
	}
	if !os.IsNotExist(certErr) && certErr != nil {
		return nil, fmt.Errorf("stat CA certificate %q: %w", certFile, certErr)
	}
	if !os.IsNotExist(keyErr) && keyErr != nil {
		return nil, fmt.Errorf("stat CA private key %q: %w", keyFile, keyErr)
	}
	if (certErr == nil) != (keyErr == nil) {
		return nil, errors.New("CA certificate and private key must either both exist or both be absent")
	}
	if err := GenerateCA(certFile, keyFile); err != nil {
		return nil, err
	}
	return Load(certFile, keyFile)
}

func Load(certFile string, keyFile string) (*Manager, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate %q: %w", certFile, err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("decode CA certificate %q: invalid PEM certificate", certFile)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate %q: %w", certFile, err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read CA private key %q: %w", keyFile, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode CA private key %q: invalid PEM private key", keyFile)
	}
	caKey := parsePrivateKey(keyBlock.Bytes)
	if caKey == nil {
		return nil, fmt.Errorf("parse CA private key %q: unsupported key format", keyFile)
	}
	if err := verifyKeyPair(caCert, caKey); err != nil {
		return nil, err
	}
	return &Manager{caCert: caCert, caKey: caKey}, nil
}

func (m *Manager) CertificateForHost(host string) (*tls.Certificate, error) {
	if m == nil || m.caCert == nil || m.caKey == nil {
		return nil, errors.New("certificate manager is not initialized")
	}
	host = normalizeHost(host)
	if host == "" {
		return nil, errors.New("certificate host is empty")
	}
	if cached, ok := m.cache.Load(host); ok {
		return cached.(*tls.Certificate), nil
	}
	cert, err := m.generateCertificate(host)
	if err != nil {
		return nil, err
	}
	actual, loaded := m.cache.LoadOrStore(host, cert)
	if loaded {
		return actual.(*tls.Certificate), nil
	}
	return cert, nil
}

func GenerateCA(certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA private key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return fmt.Errorf("generate CA serial number: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ST Core Local CA", Organization: []string{"ST Core"}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}
	if err := writeCertificate(certFile, der); err != nil {
		return err
	}
	if err := writePrivateKey(keyFile, key); err != nil {
		return err
	}
	return nil
}

func (m *Manager) generateCertificate(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate certificate key for %q: %w", host, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial number for %q: %w", host, err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate for %q: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated certificate for %q: %w", host, err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func parsePrivateKey(der []byte) crypto.Signer {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key
	}
	return nil
}

func verifyKeyPair(cert *x509.Certificate, key crypto.Signer) error {
	if cert == nil || key == nil {
		return errors.New("CA certificate and private key are required")
	}
	a, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal CA certificate public key: %w", err)
	}
	b, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("marshal CA private key public key: %w", err)
	}
	if !bytes.Equal(a, b) {
		return errors.New("CA certificate and private key do not match")
	}
	return nil
}

func writeCertificate(path string, der []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open CA certificate %q: %w", path, err)
	}
	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		file.Close()
		return fmt.Errorf("write CA certificate %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close CA certificate %q: %w", path, err)
	}
	return nil
}

func writePrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA private key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open CA private key %q: %w", path, err)
	}
	if err := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		file.Close()
		return fmt.Errorf("write CA private key %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close CA private key %q: %w", path, err)
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	return host
}
