package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
)

var cert = GenX509KeyPair()

type tlsHandler struct {
	sortedJa3    string
	ja3          string
	sortedDigest string
	ja3Digest    string
	chiLock      sync.Mutex
	chiLockState bool
}

func (t *tlsHandler) GetClientInfo(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.chiLock.Lock()
	t.chiLockState = true
	t.ja3 = JA3(info)
	t.ja3Digest = JA3Digest(t.ja3)
	jaSlice := strings.Split(strings.ReplaceAll(t.ja3, ",", "-"), "-")
	sort.Slice(jaSlice, func(i, j int) bool {
		ji, _ := strconv.Atoi(jaSlice[i])
		jj, _ := strconv.Atoi(jaSlice[j])
		return ji < jj
	})
	t.sortedDigest = JA3Digest(strings.Join(jaSlice, ","))
	t.sortedJa3 = strings.Join(jaSlice, ",")

	go func() {
		time.Sleep(time.Second)
		if t.chiLockState {
			t.chiLock.Unlock()
			t.chiLockState = false
		}
	}()

	return cert, nil
}

func (t *tlsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ja3 := t.ja3
	ja3Digest := t.ja3Digest
	if t.chiLockState {
		t.chiLock.Unlock()
	}
	t.chiLockState = false

	log.Println(r.RemoteAddr)

	fmt.Fprintf(w, `{"ja3":"%s","ja3_digest":"%s","sorted_digest":"%s","sorted_ja3":"%s"}`, ja3, ja3Digest, t.sortedDigest, t.sortedJa3)
}

func main() {
	handler := &tlsHandler{}
	listener, _ := tls.Listen("tcp", ":4443", &tls.Config{
		GetCertificate: handler.GetClientInfo,
	})
	// Start the server
	http.Serve(listener, handler)

}

// GenX509KeyPair generates the TLS keypair for the server
func GenX509KeyPair() *tls.Certificate {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:         "localhost",
			Country:            []string{"USA"},
			Organization:       []string{"localhost"},
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
		panic(err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		panic(err)
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return &outCert
}

func JA3(c *tls.ClientHelloInfo) string {
	greaseTable := map[uint16]bool{
		0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
		0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
		0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
		0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
	}

	// SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat

	s := ""
	s += fmt.Sprintf("%d,", c.Version)

	vals := []string{}
	for _, v := range c.CipherSuites {
		vals = append(vals, fmt.Sprintf("%d", v))
	}

	s += fmt.Sprintf("%s,", strings.Join(vals, "-"))

	vals = []string{}
	c.Extensions = append([]uint16{0x0000}, c.Extensions...)
	for _, v := range c.Extensions {
		if _, ok := greaseTable[v]; ok {
			continue
		}

		vals = append(vals, fmt.Sprintf("%d", v))
	}

	s += fmt.Sprintf("%s,", strings.Join(vals, "-"))

	vals = []string{}
	for _, v := range c.SupportedCurves {
		vals = append(vals, fmt.Sprintf("%d", v))
	}

	s += fmt.Sprintf("%s,", strings.Join(vals, "-"))

	vals = []string{}
	for _, v := range c.SupportedPoints {
		vals = append(vals, fmt.Sprintf("%d", v))
	}

	s += strings.Join(vals, "-")

	return s
}

func JA3Digest(ja3 string) string {
	hasher := md5.New()
	hasher.Write([]byte(ja3))
	return hex.EncodeToString(hasher.Sum(nil))
}
