package database

import (
	"fmt"

	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Init(dbPath string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("falha ao conectar ao banco (%s): %w", dbPath, err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.AccessLog{}, &models.UsedNonce{}); err != nil {
		return nil, fmt.Errorf("falha ao migrar o banco (%s): %w", dbPath, err)
	}
	return db, nil
}
