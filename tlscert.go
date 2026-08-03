package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ensureSelfSignedCert 确保 dir 下存在自签名证书,不存在则生成,
// 返回证书与私钥文件路径。SAN 覆盖 localhost、本机主机名与当前本机 IP,
// 适合本地或局域网内直接 HTTPS 访问;公网建议用正规域名与证书。
func ensureSelfSignedCert(dir string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, "ha-wbc-cert.pem")
	keyPath = filepath.Join(dir, "ha-wbc-key.pem")
	if fileExists(certPath) && fileExists(keyPath) {
		log.Printf("使用已有 TLS 证书: %s(如需让证书包含新域名,删除证书与私钥文件后重启即可自动重新生成)", certPath)
		return certPath, keyPath, nil
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}

	dnsNames := []string{"localhost"}
	if hn, err := os.Hostname(); err == nil && hn != "" && hn != "localhost" {
		dnsNames = append(dnsNames, hn)
	}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.IsGlobalUnicast() {
				ips = append(ips, ipn.IP)
			}
		}
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "HA-WBC-2 Console", Organization: []string{"ha-wbc-console"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("生成证书失败: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	log.Printf("已生成自签名 TLS 证书: %s (SAN: %v %v)", certPath, dnsNames, ips)
	return certPath, keyPath, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
