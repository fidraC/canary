package database

import (
	sqlite "github.com/glebarez/sqlite"
	uuid "github.com/uuid6/uuid6go-proto"
	"gorm.io/gorm"
)

var gen uuid.UUIDv7Generator

type Fingerprint struct {
	ID            string `gorm:"primaryKey"`
	SortedJA3     string
	UserAgent     string
	IP            string
	XForwardedFor string
	CreepID       string
	BadUA         bool
	Note          string
}
type FingerprintWithData struct {
	Fingerprint
	Data []byte
}

type CanaryNote struct {
	ID   string `gorm:"primaryKey"`
	Note string
}

var DB *gorm.DB

func init() {
	var err error
	DB, err = gorm.Open(sqlite.Open("canary.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	DB.AutoMigrate(&FingerprintWithData{}, &CanaryNote{})
}

func SaveFingerprint(fingerprint *FingerprintWithData, noteID string) {
	if noteID != "" {
		var note CanaryNote
		DB.First(&note, &CanaryNote{ID: noteID})
		fingerprint.Note = note.Note
	}
	DB.Create(fingerprint)
}

func NewNote(note string) string {
	id := gen.Next().ToString()
	DB.Create(&CanaryNote{
		ID:   id,
		Note: note,
	})
	return id
}

func GetFingerPrints() []Fingerprint {
	var fingerprints []Fingerprint
	DB.Find(&fingerprints)
	return fingerprints
}
