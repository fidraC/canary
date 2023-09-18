package fingerprinting

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fidraC/canary/creepjs"
	"github.com/fidraC/canary/crypto/tls"
	"github.com/fidraC/canary/database"
	"github.com/fidraC/canary/ja3"
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
	// Parse body as form
	form, err := url.ParseQuery(string(body))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sDInfo := form.Get("info")
	var dInfo struct {
		ID          string `json:"id"`
		Performance int    `json:"performance"`
	}
	err = json.Unmarshal([]byte(sDInfo), &dInfo)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fp_secret := form.Get("secret")

	// Remove first and last character
	fp_secret = fp_secret[1 : len(fp_secret)-1]

	var fingerprint Fingerprint

	err = creepjs.DecryptCreep(dInfo.ID, dInfo.Performance, ua, fp_secret, &fingerprint)

	if err != nil {
		err = creepjs.DecryptCreep(dInfo.ID, dInfo.Performance, "undefined", fp_secret, &fingerprint)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	resp.Fingerprint = fingerprint

	// Store fingerprint in database
	id := gen.Next()
	database.SaveFingerprint(&database.Fingerprint{
		ID:            id.ToString(),
		SortedJA3:     t.sortedDigest,
		UserAgent:     ua,
		IP:            ip_addr,
		XForwardedFor: forwarded,
		CreepID:       dInfo.ID,
		Data:          resp.String(),
	})

	w.Header().Set("Content-Type", "application/json")

	fmt.Fprint(w, resp.String())
}
