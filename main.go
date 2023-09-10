package main

import (
	"net/http"

	"github.com/fidraC/QRCanary/fingerprinting"
)

func main() {
	ja3Handler := fingerprinting.NewHandler()
	listener, err := fingerprinting.NewListener(ja3Handler)
	if err != nil {
		panic(err)
	}
	router := http.NewServeMux()
	router.HandleFunc("/ja3", ja3Handler.ServeHTTP)
	http.Serve(listener, router)

}
