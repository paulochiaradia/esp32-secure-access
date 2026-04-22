package database

import (
	"testing"
	"time"

	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newAdminModelsTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("erro ao abrir banco de teste: %v", err)
	}

	err = db.AutoMigrate(&models.AdminUser{}, &models.AdminRefreshSession{}, &models.AdminAuditLog{})
	if err != nil {
		t.Fatalf("erro ao fazer automigrate dos modelos admin: %v", err)
	}

	return db
}

func TestAdminUser_UsernameMustBeUnique(t *testing.T) {
	db := newAdminModelsTestDB(t)

	first := models.AdminUser{Username: "admin", PasswordHash: "hash-1", Role: "admin", Active: true}
	if err := db.Create(&first).Error; err != nil {
		t.Fatalf("erro ao criar primeiro admin: %v", err)
	}

	duplicate := models.AdminUser{Username: "admin", PasswordHash: "hash-2", Role: "admin", Active: true}
	if err := db.Create(&duplicate).Error; err == nil {
		t.Fatalf("era esperado erro de unicidade para username duplicado")
	}
}

func TestAdminRefreshSession_TokenHashMustBeUnique(t *testing.T) {
	db := newAdminModelsTestDB(t)

	admin := models.AdminUser{Username: "admin2", PasswordHash: "hash-1", Role: "admin", Active: true}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("erro ao criar admin: %v", err)
	}

	first := models.AdminRefreshSession{
		AdminUserID: admin.ID,
		TokenHash:   "token-hash-1",
		JTI:         "jti-1",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	if err := db.Create(&first).Error; err != nil {
		t.Fatalf("erro ao criar primeira sessao: %v", err)
	}

	duplicateToken := models.AdminRefreshSession{
		AdminUserID: admin.ID,
		TokenHash:   "token-hash-1",
		JTI:         "jti-2",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	if err := db.Create(&duplicateToken).Error; err == nil {
		t.Fatalf("era esperado erro de unicidade para token_hash duplicado")
	}
}
