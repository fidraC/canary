package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

type tlsHandler struct {
	chi *tls.ClientHelloInfo
}

func (t *tlsHandler) GetClientInfo(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.chi = info
	return GenX509KeyPair()
}

func (t *tlsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if t.chi == nil {
		fmt.Fprintln(w, "No TLS ClientHelloInfo")
		return
	}
	fmt.Fprintln(w, t.chi.CipherSuites)
}

func main() {
	handler := &tlsHandler{}

	s := &http.Server{
		Addr: ":9000",
		TLSConfig: &tls.Config{
			GetCertificate: handler.GetClientInfo,
		},
		Handler: handler,
	}

	log.Fatalln(s.ListenAndServeTLS("", ""))
}

// GenX509KeyPair generates the TLS keypair for the server
func GenX509KeyPair() (*tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:         "quickserve.example.com",
			Country:            []string{"USA"},
			Organization:       []string{"example.com"},
			OrganizationalUnit: []string{"quickserve"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1), // Valid for one day
		SubjectKeyId:          []byte{113, 117, 105, 99, 107, 115, 101, 114, 118, 101},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return &tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return &tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return &outCert, nil
}
