package repositories

import (
	"errors"

	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/gorm"
)

var ErrUserNotFound = errors.New("user not found")

type AccessRepository interface {
	FindActiveUserByUID(uid string) (*models.User, error)
	CreateAccessLog(accessLog *models.AccessLog) error
}

type GormAccessRepository struct {
	DB *gorm.DB
}

func NewAccessRepository(db *gorm.DB) *GormAccessRepository {
	return &GormAccessRepository{DB: db}
}

func (r *GormAccessRepository) FindActiveUserByUID(uid string) (*models.User, error) {
	var user models.User
	if err := r.DB.Where("uid = ? AND active = ?", uid, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (r *GormAccessRepository) CreateAccessLog(accessLog *models.AccessLog) error {
	return r.DB.Create(accessLog).Error
}
