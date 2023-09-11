package static

import (
	"embed"
	"fmt"
	"net/http"
	"strings"
)

//go:embed dist
var staticFS embed.FS

func StaticHandler(w http.ResponseWriter, r *http.Request) {
	var file []byte
	var err error
	if r.URL.Path == "/" {
		r.URL.Path = "/index.html"
	}
	file, err = staticFS.ReadFile(fmt.Sprintf("dist%s", r.URL.Path))
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

	w.Write(file)

}
