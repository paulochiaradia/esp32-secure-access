package repositories

import (
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/gorm"
)

type AccessLogRepository interface {
	CreateAccessLog(accessLog *models.AccessLog) error
}

type GormAccessLogRepository struct {
	DB *gorm.DB
}

func NewAccessLogRepository(db *gorm.DB) *GormAccessLogRepository {
	return &GormAccessLogRepository{DB: db}
}

func (r *GormAccessLogRepository) CreateAccessLog(accessLog *models.AccessLog) error {
	return r.DB.Create(accessLog).Error
}
