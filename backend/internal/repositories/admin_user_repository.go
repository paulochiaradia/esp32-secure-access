package repositories

import (
	"errors"

	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/gorm"
)

var ErrAdminUserNotFound = errors.New("admin user not found")

type AdminUserRepository interface {
	FindActiveByUsername(username string) (*models.AdminUser, error)
}

type GormAdminUserRepository struct {
	DB *gorm.DB
}

func NewAdminUserRepository(db *gorm.DB) *GormAdminUserRepository {
	return &GormAdminUserRepository{DB: db}
}

func (r *GormAdminUserRepository) FindActiveByUsername(username string) (*models.AdminUser, error) {
	var admin models.AdminUser
	if err := r.DB.Where("username = ? AND active = ?", username, true).First(&admin).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAdminUserNotFound
		}
		return nil, err
	}

	return &admin, nil
}
