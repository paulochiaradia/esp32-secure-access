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

	if err := db.AutoMigrate(&models.PendingRegistration{}, &models.AdminRefreshSession{}); err != nil {
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

	var countOldUnscoped int64
	if err := db.Unscoped().Model(&models.PendingRegistration{}).Where("uid = ?", "TAG-OLD").Count(&countOldUnscoped).Error; err != nil {
		t.Fatalf("erro ao contar registro antigo em unscoped: %v", err)
	}
	if countOldUnscoped != 0 {
		t.Fatalf("registro antigo deveria ter sido removido fisicamente, contagem unscoped %d", countOldUnscoped)
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

func TestCleanExpiredAdminRefreshSessions_RemovesOnlyExpiredSessions(t *testing.T) {
	db := newDatabaseTestDB(t)

	expired := models.AdminRefreshSession{AdminUserID: 1, TokenHash: "expired-hash", JTI: "expired-jti", IssuedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-1 * time.Hour)}
	active := models.AdminRefreshSession{AdminUserID: 1, TokenHash: "active-hash", JTI: "active-jti", IssuedAt: time.Now().Add(-30 * time.Minute), ExpiresAt: time.Now().Add(2 * time.Hour)}

	if err := db.Create(&expired).Error; err != nil {
		t.Fatalf("erro ao inserir sessao expirada: %v", err)
	}
	if err := db.Create(&active).Error; err != nil {
		t.Fatalf("erro ao inserir sessao ativa: %v", err)
	}

	if err := CleanExpiredAdminRefreshSessions(db); err != nil {
		t.Fatalf("erro ao limpar sessoes expiradas: %v", err)
	}

	var expiredCount int64
	if err := db.Unscoped().Model(&models.AdminRefreshSession{}).Where("token_hash = ?", "expired-hash").Count(&expiredCount).Error; err != nil {
		t.Fatalf("erro ao contar sessao expirada: %v", err)
	}
	if expiredCount != 0 {
		t.Fatalf("sessao expirada deveria ser removida fisicamente")
	}

	var activeCount int64
	if err := db.Model(&models.AdminRefreshSession{}).Where("token_hash = ?", "active-hash").Count(&activeCount).Error; err != nil {
		t.Fatalf("erro ao contar sessao ativa: %v", err)
	}
	if activeCount != 1 {
		t.Fatalf("sessao ativa deveria permanecer")
	}
}
