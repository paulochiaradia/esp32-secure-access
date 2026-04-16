package repositories

import (
	"errors"
	"time"

	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/gorm"
)

type NonceRepository interface {
	Exists(uid string, nonce string) (bool, error)
	Save(usedNonce *models.UsedNonce) error
	DeleteExpired(now time.Time) error
}

type GormNonceRepository struct {
	DB *gorm.DB
}

func NewNonceRepository(db *gorm.DB) *GormNonceRepository {
	return &GormNonceRepository{DB: db}
}

func (r *GormNonceRepository) Exists(uid string, nonce string) (bool, error) {
	var usedNonce models.UsedNonce
	err := r.DB.Where("uid = ? AND nonce = ?", uid, nonce).First(&usedNonce).Error
	if err == nil {
		return true, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return false, err
}

func (r *GormNonceRepository) Save(usedNonce *models.UsedNonce) error {
	return r.DB.Create(usedNonce).Error
}

func (r *GormNonceRepository) DeleteExpired(now time.Time) error {
	return r.DB.Where("expires_at <= ?", now).Delete(&models.UsedNonce{}).Error
}
