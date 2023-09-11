package main

import (
	"log"
	"net/http"

	"github.com/fidraC/canary/api/fingerprinting"
	"github.com/fidraC/canary/static"
)

func main() {
	fingerprinter := fingerprinting.NewHandler(nil)
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
