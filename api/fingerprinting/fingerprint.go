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
	"github.com/fidraC/canary/ja3"
	"github.com/fidraC/canary/utils"
)

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
	resp := utils.JSON{
		"ja3":             t.ja3,
		"ja3_digest":      t.ja3Digest,
		"nja3_digest":     t.sortedDigest,
		"ua":              ua,
		"ip":              ip_addr,
		"x-forwarded-for": forwarded,
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

	fp, err := creepjs.DecryptCreep(dInfo.ID, dInfo.Performance, ua, fp_secret)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp["fingerprint"] = fp

	w.Header().Set("Content-Type", "application/json")

	fmt.Fprint(w, resp)
}
