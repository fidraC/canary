package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"strings"

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
		// Determine content type based on file extension
		contentType := "text/plain"
		switch {
		case strings.HasSuffix(r.URL.Path, ".html"):
			contentType = "text/html"
		case strings.HasSuffix(r.URL.Path, ".css"):
			contentType = "text/css"
		case strings.HasSuffix(r.URL.Path, ".js"):
			contentType = "application/javascript"
		case strings.HasSuffix(r.URL.Path, ".png"):
			contentType = "image/png"
		case strings.HasSuffix(r.URL.Path, ".ico"):
			contentType = "image/x-icon"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Security-Policy", "default-src *")

		w.Write(file)

	})
	log.Println("Listening on :4443")
	http.Serve(listener, router)

}
