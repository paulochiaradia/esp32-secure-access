package database

import (
	"log"
	"os"
	"time"

	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Init(dbPath string) *gorm.DB {
	// Configura um logger customizado para o GORM
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Error,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: newLogger, // Aplica o novo logger
	})

	if err != nil {
		log.Fatalf("Falha ao conectar ao banco: %v", err)
	}

	db.AutoMigrate(&models.User{}, &models.AccessLog{}, &models.UsedNonce{})
	return db
}
