package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"

	"github.com/fidraC/canary/api/fingerprinting"
)

// Embed static/ directory into binary
//
//go:embed static
var staticFS embed.FS

func main() {
	fingerprinter := fingerprinting.NewHandler()
	listener, err := fingerprinting.NewListener(fingerprinter)
	if err != nil {
		panic(err)
	}
	router := http.NewServeMux()
	router.HandleFunc("/finger", fingerprinter.ServeHTTP)
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var file []byte
		var err error
		if r.URL.Path == "/" {
			r.URL.Path = "/index.html"
		}
		file, err = staticFS.ReadFile(fmt.Sprintf("static%s", r.URL.Path))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(err.Error()))
			return
		}
		w.Write(file)

	})
	log.Println("Listening on :4443")
	http.Serve(listener, router)

}
