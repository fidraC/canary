package utils

import "encoding/json"

type JSON map[string]interface{}

func (j JSON) String() string {
	b, err := json.Marshal(j)
	if err != nil {
		return ""
	}
	return string(b)
}

func Stringify(i interface{}) string {
	b, err := json.Marshal(i)
	if err != nil {
		return ""
	}
	return string(b)
}
