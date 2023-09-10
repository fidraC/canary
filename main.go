package main

import (
	"net/http"

	"github.com/fidraC/QRCanary/fingerprinting"
)

func main() {
	handler := fingerprinting.NewHandler()
	listener, err := fingerprinting.NewListener(handler)
	if err != nil {
		panic(err)
	}
	// Start the server
	http.Serve(listener, handler)

}
