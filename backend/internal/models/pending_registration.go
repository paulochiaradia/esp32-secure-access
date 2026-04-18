package models

import (
	"time"

	"gorm.io/gorm"
)

type PendingRegistration struct {
	gorm.Model
	UID          string `gorm:"uniqueIndex"`
	AttemptCount int    `gorm:"default:1"`
	LastSeen     time.Time
}

// Struct para o payload de aprovação
type CreateUserRequest struct {
	UID  string `json:"uid" binding:"required"`
	Name string `json:"name" binding:"required"`
}
