package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/fidraC/canary/crypto/tls"
)

func String(c *tls.ClientHelloInfo) string {
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

func Hash(ja3 string) string {
	hasher := md5.New()
	hasher.Write([]byte(ja3))
	return hex.EncodeToString(hasher.Sum(nil))
}
