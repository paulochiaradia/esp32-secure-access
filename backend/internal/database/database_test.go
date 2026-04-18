package database

import (
	"testing"
	"time"

	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newDatabaseTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("erro ao abrir banco de teste: %v", err)
	}

	if err := db.AutoMigrate(&models.PendingRegistration{}); err != nil {
		t.Fatalf("erro ao fazer automigrate da tabela de pendências: %v", err)
	}

	return db
}

func TestCleanOldPendingRegistrations_RemovesOnlyOlderThanOneHour(t *testing.T) {
	db := newDatabaseTestDB(t)

	oldRecord := models.PendingRegistration{UID: "TAG-OLD", AttemptCount: 1, LastSeen: time.Now().Add(-2 * time.Hour)}
	recentRecord := models.PendingRegistration{UID: "TAG-RECENT", AttemptCount: 1, LastSeen: time.Now().Add(-20 * time.Minute)}
	borderlineRecord := models.PendingRegistration{UID: "TAG-BORDER", AttemptCount: 1, LastSeen: time.Now().Add(-59 * time.Minute)}

	if err := db.Create(&oldRecord).Error; err != nil {
		t.Fatalf("erro ao inserir registro antigo: %v", err)
	}
	if err := db.Create(&recentRecord).Error; err != nil {
		t.Fatalf("erro ao inserir registro recente: %v", err)
	}
	if err := db.Create(&borderlineRecord).Error; err != nil {
		t.Fatalf("erro ao inserir registro limítrofe: %v", err)
	}

	if err := CleanOldPendingRegistrations(db); err != nil {
		t.Fatalf("erro ao limpar pendências antigas: %v", err)
	}

	var countOld int64
	if err := db.Model(&models.PendingRegistration{}).Where("uid = ?", "TAG-OLD").Count(&countOld).Error; err != nil {
		t.Fatalf("erro ao contar registro antigo: %v", err)
	}
	if countOld != 0 {
		t.Fatalf("registro antigo deveria ter sido removido, mas ainda existem %d", countOld)
	}

	var countRecent int64
	if err := db.Model(&models.PendingRegistration{}).Where("uid = ?", "TAG-RECENT").Count(&countRecent).Error; err != nil {
		t.Fatalf("erro ao contar registro recente: %v", err)
	}
	if countRecent != 1 {
		t.Fatalf("registro recente deveria permanecer, contagem atual %d", countRecent)
	}

	var countBorder int64
	if err := db.Model(&models.PendingRegistration{}).Where("uid = ?", "TAG-BORDER").Count(&countBorder).Error; err != nil {
		t.Fatalf("erro ao contar registro limítrofe: %v", err)
	}
	if countBorder != 1 {
		t.Fatalf("registro limítrofe deveria permanecer, contagem atual %d", countBorder)
	}
}
