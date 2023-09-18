package config

import "os"

var ConfigureSecret string = "changeme"

func init() {
	if os.Getenv("CONFIGURE_SECRET") != "" {
		ConfigureSecret = os.Getenv("CONFIGURE_SECRET")
	}
}
