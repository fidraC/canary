package database

import (
	sqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type Fingerprint struct {
	ID            string `gorm:"primaryKey"`
	SortedJA3     string
	UserAgent     string
	IP            string
	XForwardedFor string
	CreepID       string
	Data          string
}

var DB *gorm.DB

func init() {
	var err error
	DB, err = gorm.Open(sqlite.Open("canary.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	DB.AutoMigrate(&Fingerprint{})
}

func SaveFingerprint(fingerprint *Fingerprint) {
	DB.Create(fingerprint)
}
