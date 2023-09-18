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
	Data          string
	BadUA         bool
	Note          string
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
	DB.AutoMigrate(&Fingerprint{}, &CanaryNote{})
}

func SaveFingerprint(fingerprint *Fingerprint, noteID string) {
	if noteID != "" {
		var note CanaryNote
		DB.First(&note, noteID)
		fingerprint.Note = note.Note
	}

	DB.Create(fingerprint)
}

func NewNote(note string) {
	DB.Create(&CanaryNote{
		ID:   gen.Next().ToString(),
		Note: note,
	})
}
