package creepjs

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/fidraC/canary/cryptojs"
)

func DecryptCreep(creepID string, perf int, ua, fp_secret string) (any, error) {
	charCodes := make([]int, len(creepID))
	for i, c := range creepID {
		charCodes[i] = int(c) + (perf % 24)
	}
	creepID = string(runeSliceToRune(charCodes))

	ceilToHourTime := int64(time.Now().Add(time.Hour-time.Duration(time.Now().Minute())*time.Minute-time.Duration(time.Now().Second())*time.Second).Round(time.Hour).UnixNano() / 1e6)

	secretKey := fmt.Sprintf("%s%s%d", creepID, ua, ceilToHourTime)
	fp_string, err := cryptojs.AesDecrypt(fp_secret, secretKey)
	if err != nil {
		return nil, err
	}
	var fp any
	err = json.Unmarshal([]byte(fp_string), &fp)
	if err != nil {
		return nil, err
	}
	return fp, nil
}

func runeSliceToRune(slice []int) []rune {
	result := make([]rune, len(slice))
	for i, v := range slice {
		result[i] = rune(v)
	}
	return result
}
