package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/fidraC/canary/api/fingerprinting"
	"github.com/fidraC/canary/crypto/tls"
	"github.com/fidraC/canary/static"
)

func main() {
	certPath := flag.String("cert", "", "Path to TLS certificate")
	privKeyPath := flag.String("key", "", "Path to TLS private key")
	flag.Parse()
	var fingerprinter *fingerprinting.TLSHandler
	if *certPath == "" || *privKeyPath == "" {
		fingerprinter = fingerprinting.NewHandler(nil)
	} else {
		cert, err := tls.LoadX509KeyPair(*certPath, *privKeyPath)
		if err != nil {
			panic(err)
		}
		fingerprinter = fingerprinting.NewHandler(&cert)
	}
	listener, err := fingerprinting.NewListener(fingerprinter)
	if err != nil {
		panic(err)
	}
	router := http.NewServeMux()
	router.HandleFunc("/finger", fingerprinter.ServeHTTP)
	router.HandleFunc("/", static.StaticHandler)
	log.Println("Listening on :4443")
	http.Serve(listener, router)

}
