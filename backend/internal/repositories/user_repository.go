package repositories

import (
	"errors"

	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/gorm"
)

var ErrUserNotFound = errors.New("user not found")

type UserRepository interface {
	FindActiveUserByUID(uid string) (*models.User, error)
}

type GormUserRepository struct {
	DB *gorm.DB
}

func NewUserRepository(db *gorm.DB) *GormUserRepository {
	return &GormUserRepository{DB: db}
}

func (r *GormUserRepository) FindActiveUserByUID(uid string) (*models.User, error) {
	var user models.User
	if err := r.DB.Where("uid = ? AND active = ?", uid, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}
