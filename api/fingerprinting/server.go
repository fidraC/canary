package fingerprinting

import (
	"net"

	"github.com/fidraC/canary/crypto/tls"
)

func NewHandler(certificate *tls.Certificate) *TLSHandler {
	if certificate != nil {
		return &TLSHandler{
			TLSCert: certificate,
		}
	}
	return &TLSHandler{
		TLSCert: GenX509KeyPair(),
	}
}

func NewListener(handler *TLSHandler) (net.Listener, error) {
	return tls.Listen("tcp", ":443", &tls.Config{
		GetCertificate: handler.GetCertificate,
	})
}
