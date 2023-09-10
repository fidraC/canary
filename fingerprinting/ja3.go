package fingerprinting

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fidraC/QRCanary/utils"
	"github.com/honeytrap/honeytrap/services/ja3/crypto/tls"
)

func NewHandler() *TLSHandler {
	return &TLSHandler{
		TLSCert: GenX509KeyPair(),
	}
}

func NewListener(handler *TLSHandler) (net.Listener, error) {
	return tls.Listen("tcp", ":4443", &tls.Config{
		GetCertificate: handler.GetCertificate,
	})
}

type TLSHandler struct {
	sortedJa3    string
	ja3          string
	sortedDigest string
	ja3Digest    string
	chiLock      sync.Mutex
	chiLockState bool
	TLSCert      *tls.Certificate
}

func (t *TLSHandler) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.chiLock.Lock()
	t.chiLockState = true

	t.ja3 = JA3(info)
	t.ja3Digest = JA3Digest(t.ja3)

	// Sort extensions
	sort.Slice(info.Extensions, func(i, j int) bool {
		return info.Extensions[i] < info.Extensions[j]
	})
	t.sortedJa3 = JA3(info)
	t.sortedDigest = JA3Digest(t.sortedJa3)

	go func() {
		time.Sleep(time.Second)
		if t.chiLockState {
			t.chiLock.Unlock()
			t.chiLockState = false
		}
	}()

	return t.TLSCert, nil
}

func (t *TLSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp := utils.JSON{
		"ja3":        t.ja3,
		"ja3_digest": t.ja3Digest,
		"sorted": utils.JSON{
			"ja3":        t.sortedJa3,
			"ja3_digest": t.sortedDigest,
		},
	}
	if t.chiLockState {
		t.chiLock.Unlock()
	}
	t.chiLockState = false

	w.Header().Set("Content-Type", "application/json")

	fmt.Fprint(w, resp)

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
		if _, ok := greaseTable[v]; ok {
			continue
		}
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
		if _, ok := greaseTable[uint16(v)]; ok {
			continue
		}
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
