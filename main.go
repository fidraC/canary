package main

import (
	"net/http"

	"github.com/fidraC/canary/api/fingerprinting"
)

func main() {
	fingerprinter := fingerprinting.NewHandler()
	listener, err := fingerprinting.NewListener(fingerprinter)
	if err != nil {
		panic(err)
	}
	router := http.NewServeMux()
	router.HandleFunc("/finger", fingerprinter.ServeHTTP)
	http.Serve(listener, router)

}
