package canaries

import (
	"net/http"

	"github.com/fidraC/canary/config"
	"github.com/fidraC/canary/database"
)

func ConfigureHandler(w http.ResponseWriter, r *http.Request) {
	// Get form data
	note := r.FormValue("note")
	secret := r.FormValue("secret")
	if secret != config.ConfigureSecret {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	id := database.NewNote(note)
	// Get Origin
	origin := r.Header.Get("Origin")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(origin + "/" + id))
}
