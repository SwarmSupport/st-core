package certificate

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// InstallCA and RemoveCA manage trust for the current user only.
func InstallCA(certFile string) error {
	if _, err := readCA(certFile); err != nil {
		return err
	}
	abs, err := filepath.Abs(certFile)
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "darwin":
		keychain, err := loginKeychain()
		if err != nil {
			return err
		}
		return runTrust("security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, abs)
	case "windows":
		return runTrust("certutil", "-user", "-addstore", "Root", abs)
	default:
		return fmt.Errorf("CA trust installation is unsupported on %s", runtime.GOOS)
	}
}

func RemoveCA(certFile string) error {
	cert, err := readCA(certFile)
	if err != nil {
		return err
	}
	digest := sha1.Sum(cert.Raw)
	fingerprint := strings.ToUpper(hex.EncodeToString(digest[:]))
	switch runtime.GOOS {
	case "darwin":
		keychain, err := loginKeychain()
		if err != nil {
			return err
		}
		return runTrust("security", "delete-certificate", "-Z", fingerprint, "-k", keychain)
	case "windows":
		return runTrust("certutil", "-user", "-delstore", "Root", fingerprint)
	default:
		return fmt.Errorf("CA trust removal is unsupported on %s", runtime.GOOS)
	}
}

func readCA(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid CA certificate PEM %q", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate %q is not a CA", path)
	}
	return cert, nil
}

func loginKeychain() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

func runTrust(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}
