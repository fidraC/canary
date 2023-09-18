package fingerprinting

import "encoding/json"

type FullFingerprint struct {
	Fingerprint         any    `json:"fingerprint"`
	IP                  string `json:"ip"`
	Ja3                 string `json:"ja3"`
	Ja3Digest           string `json:"ja3_digest"`
	NormalizedJa3Digest string `json:"nja3_digest"`
	UserAgent           string `json:"ua"`
	XForwardedFor       string `json:"x-forwarded-for"`
}

func (f *FullFingerprint) String() []byte {
	str, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	return str
}
