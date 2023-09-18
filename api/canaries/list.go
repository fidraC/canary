package canaries

import (
	"fmt"
	"net/http"

	"github.com/fidraC/canary/database"
	"github.com/fidraC/canary/utils"
)

func HandleGetCanaries(w http.ResponseWriter, r *http.Request) {
	fingerprints := database.GetFingerPrints()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, utils.Stringify(fingerprints))
}
