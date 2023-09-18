package fingerprinting

import "encoding/json"

type BrowserInfo struct {
	Audio                        string        `json:"audio"`
	Benchmark                    int           `json:"benchmark"`
	BenchmarkProto               int           `json:"benchmarkProto"`
	Canvas                       string        `json:"canvas"`
	Client                       []string      `json:"client"`
	CSSAnyHover                  string        `json:"cssAnyHover"`
	CSSAnyPointer                string        `json:"cssAnyPointer"`
	CSSColorGamut                string        `json:"cssColorGamut"`
	CSSColorScheme               string        `json:"cssColorScheme"`
	CSSDeviceAspectRatio         string        `json:"cssDeviceAspectRatio"`
	CSSDeviceScreen              string        `json:"cssDeviceScreen"`
	CSSDisplayMode               string        `json:"cssDisplayMode"`
	CSSForcedColors              string        `json:"cssForcedColors"`
	CSSHover                     string        `json:"cssHover"`
	CSSMedia                     string        `json:"cssMedia"`
	CSSMonochrome                string        `json:"cssMonochrome"`
	CSSOrientation               string        `json:"cssOrientation"`
	CSSPointer                   string        `json:"cssPointer"`
	CSSReducedMotion             string        `json:"cssReducedMotion"`
	Device                       []interface{} `json:"device"`
	EmojiDOMRect                 float64       `json:"emojiDOMRect"`
	EmojiPixels                  float64       `json:"emojiPixels"`
	EmojiSVGRect                 float64       `json:"emojiSVGRect"`
	EmojiSetDOMRect              string        `json:"emojiSetDOMRect"`
	EmojiSetPixels               string        `json:"emojiSetPixels"`
	EmojiSetSVGRect              string        `json:"emojiSetSVGRect"`
	EmojiSetTextMetrics          string        `json:"emojiSetTextMetrics"`
	EmojiTextMetrics             float64       `json:"emojiTextMetrics"`
	Engine                       string        `json:"engine"`
	Features                     string        `json:"features"`
	FontList                     []string      `json:"fontList"`
	Fonts                        string        `json:"fonts"`
	GPU                          []string      `json:"gpu"`
	GPUBrand                     string        `json:"gpuBrand"`
	Headless                     string        `json:"headless"`
	HeadlessHasBadChromeRuntime  bool          `json:"headlessHasBadChromeRuntime"`
	HeadlessHasBadWebGL          bool          `json:"headlessHasBadWebGL"`
	HeadlessHasHeadlessUA        bool          `json:"headlessHasHeadlessUA"`
	HeadlessHasHeadlessWorkerUA  bool          `json:"headlessHasHeadlessWorkerUA"`
	HeadlessHasHighChromeIndex   bool          `json:"headlessHasHighChromeIndex"`
	HeadlessHasIframeProxy       bool          `json:"headlessHasIframeProxy"`
	HeadlessHasKnownBgColor      bool          `json:"headlessHasKnownBgColor"`
	HeadlessHasPermissionsBug    bool          `json:"headlessHasPermissionsBug"`
	HeadlessHasSwiftShader       bool          `json:"headlessHasSwiftShader"`
	HeadlessHasToStringProxy     bool          `json:"headlessHasToStringProxy"`
	HeadlessHasVvpScreenRes      bool          `json:"headlessHasVvpScreenRes"`
	HeadlessLikeRating           int           `json:"headlessLikeRating"`
	HeadlessNoChrome             bool          `json:"headlessNoChrome"`
	HeadlessNoContactsManager    bool          `json:"headlessNoContactsManager"`
	HeadlessNoContentIndex       bool          `json:"headlessNoContentIndex"`
	HeadlessNoDownlinkMax        bool          `json:"headlessNoDownlinkMax"`
	HeadlessNoMimeTypes          bool          `json:"headlessNoMimeTypes"`
	HeadlessNoPlugins            bool          `json:"headlessNoPlugins"`
	HeadlessNoTaskbar            bool          `json:"headlessNoTaskbar"`
	HeadlessNoWebShare           bool          `json:"headlessNoWebShare"`
	HeadlessNotificationIsDenied bool          `json:"headlessNotificationIsDenied"`
	HeadlessPdfIsDisabled        bool          `json:"headlessPdfIsDisabled"`
	HeadlessPrefersLightColor    bool          `json:"headlessPrefersLightColor"`
	HeadlessRating               int           `json:"headlessRating"`
	HeadlessStealthRating        int           `json:"headlessStealthRating"`
	HeadlessSystemFont           string        `json:"headlessSystemFont"`
	HeadlessUaDataIsBlank        bool          `json:"headlessUaDataIsBlank"`
	HeadlessWebDriverIsOn        bool          `json:"headlessWebDriverIsOn"`
	ImageDataLowEntropy          string        `json:"imageDataLowEntropy"`
	Measured                     int           `json:"measured"`
	Memory                       interface{}   `json:"memory"`
	MemoryGB                     interface{}   `json:"memoryGB"`
	Quota                        int64         `json:"quota"`
	QuotaGB                      int           `json:"quotaGB"`
	QuotaIsInsecure              bool          `json:"quotaIsInsecure"`
	Resistance                   string        `json:"resistance"`
	ResistanceExt                interface{}   `json:"resistanceExt"`
	Screen                       []interface{} `json:"screen"`
	ScriptSize                   int           `json:"scriptSize"`
	Scripts                      []string      `json:"scripts"`
	StackBytes                   string        `json:"stackBytes"`
	StackSize                    int           `json:"stackSize"`
	Timezone                     []interface{} `json:"timezone"`
	TimingRes                    []int         `json:"timingRes"`
	Ttfb                         interface{}   `json:"ttfb"`
	UserAgent                    string        `json:"userAgent"`
	UserAgentDevice              []string      `json:"userAgentDevice"`
	WebRTCCodecs                 string        `json:"webRTCCodecs"`
	WebRTCFoundation             string        `json:"webRTCFoundation"`
	WebRTCMediaDevices           []string      `json:"webRTCMediaDevices"`
	Webgl                        string        `json:"webgl"`
	WebglBrandCapabilities       string        `json:"webglBrandCapabilities"`
	WebglCapabilities            int64         `json:"webglCapabilities"`
	WebglParams                  string        `json:"webglParams"`
	WorkerEnabled                string        `json:"workerEnabled"`
}
type Summary struct {
	BotHash      string      `json:"botHash"`
	CanvasHash   string      `json:"canvasHash"`
	ErrorsLen    int         `json:"errorsLen"`
	Fuzzy        string      `json:"fuzzy"`
	GlBc         string      `json:"glBc"`
	ID           string      `json:"id"`
	LiesLen      int         `json:"liesLen"`
	Measured     int         `json:"measured"`
	Perf         string      `json:"perf"`
	Resistance   string      `json:"resistance"`
	SQuota       int64       `json:"sQuota"`
	ScreenHash   string      `json:"screenHash"`
	StackBytes   string      `json:"stackBytes"`
	SubID        string      `json:"subId"`
	TimeZoneHash string      `json:"timeZoneHash"`
	TmSum        float64     `json:"tmSum"`
	TrashLen     int         `json:"trashLen"`
	Ttfb         interface{} `json:"ttfb"`
	WebglHash    string      `json:"webglHash"`
}

type Fingerprint struct {
	Browser BrowserInfo `json:"browser"`
	Summary Summary     `json:"summary"`
}

type FullFingerprint struct {
	Fingerprint         Fingerprint `json:"fingerprint"`
	IP                  string      `json:"ip"`
	Ja3                 string      `json:"ja3"`
	Ja3Digest           string      `json:"ja3_digest"`
	NormalizedJa3Digest string      `json:"nja3_digest"`
	UserAgent           string      `json:"ua"`
	XForwardedFor       string      `json:"x-forwarded-for"`
}

func (f *FullFingerprint) String() string {
	str, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	return string(str)
}
