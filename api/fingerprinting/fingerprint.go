package fingerprinting

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fidraC/canary/creepjs"
	"github.com/fidraC/canary/crypto/tls"
	"github.com/fidraC/canary/database"
	"github.com/fidraC/canary/ja3"
	"github.com/fidraC/canary/utils"
	uuid "github.com/uuid6/uuid6go-proto"
)

var gen uuid.UUIDv7Generator

type TLSHandler struct {
	ja3          string
	sortedDigest string
	ja3Digest    string
	chiLock      sync.Mutex
	chiLockState bool
	TLSCert      *tls.Certificate
}

func (t *TLSHandler) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.chiLock.Lock()
	t.chiLockState = true

	t.ja3 = ja3.String(info)
	t.ja3Digest = ja3.Hash(t.ja3)

	// Sort extensions
	sort.Slice(info.Extensions, func(i, j int) bool {
		return info.Extensions[i] < info.Extensions[j]
	})
	sortedJa3 := ja3.String(info)
	t.sortedDigest = ja3.Hash(sortedJa3)

	go func() {
		time.Sleep(time.Second)
		if t.chiLockState {
			t.chiLock.Unlock()
			t.chiLockState = false
		}
	}()

	return t.TLSCert, nil
}

func (t *TLSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ua := r.Header.Get("User-Agent")
	ip_addr := strings.Split(r.RemoteAddr, ":")[0]
	forwarded := r.Header.Get("X-FORWARDED-FOR")
	resp := FullFingerprint{
		Ja3:                 t.ja3,
		Ja3Digest:           t.ja3Digest,
		NormalizedJa3Digest: t.sortedDigest,
		UserAgent:           ua,
		IP:                  ip_addr,
		XForwardedFor:       forwarded,
	}
	if t.chiLockState {
		t.chiLock.Unlock()
	}
	t.chiLockState = false

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		Secret string `json:"secret"`
		Keys   struct {
			ID          string `json:"id"`
			Performance int    `json:"performance"`
			UA          string `json:"ua"`
		} `json:"keys"`
	}

	err = json.Unmarshal(body, &req)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var browserInfo BrowserInfo

	err = creepjs.DecryptCreep(req.Keys.ID, req.Keys.Performance, req.Keys.UA, req.Secret, &browserInfo)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return

	}

	resp.Fingerprint = browserInfo

	// Store fingerprint in database
	id := gen.Next()
	database.SaveFingerprint(&database.Fingerprint{
		ID:            id.ToString(),
		SortedJA3:     t.sortedDigest,
		UserAgent:     ua,
		IP:            ip_addr,
		XForwardedFor: forwarded,
		CreepID:       req.Keys.ID,
		Data:          resp.String(),
		BadUA:         ua != req.Keys.UA,
	})

	if ua != req.Keys.UA {
		log.Println("Bad UA")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, utils.JSON{
		"redirect": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
	})
}
