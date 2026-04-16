package database

import (
	"log"

	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Init(dbPath string) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Falha ao conectar ao banco (%s): %v", dbPath, err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.AccessLog{}); err != nil {
		log.Fatalf("Falha ao migrar o banco (%s): %v", dbPath, err)
	}
	return db
}
