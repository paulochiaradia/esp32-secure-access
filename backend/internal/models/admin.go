package models

import (
	"time"

	"gorm.io/gorm"
)

// AdminUser representa um usuario autorizado a acessar rotas administrativas.
type AdminUser struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex;size:100;not null"`
	PasswordHash string `gorm:"size:255;not null"`
	Role         string `gorm:"size:20;not null;default:viewer"`
	Active       bool   `gorm:"not null;default:true"`
}

// AdminRefreshSession armazena a sessao de refresh token para suportar rotacao e revogacao.
type AdminRefreshSession struct {
	gorm.Model
	AdminUserID         uint      `gorm:"not null;index"`
	TokenHash           string    `gorm:"size:255;not null;uniqueIndex"`
	JTI                 string    `gorm:"size:100;not null;uniqueIndex"`
	IssuedAt            time.Time `gorm:"not null"`
	ExpiresAt           time.Time `gorm:"not null;index"`
	RevokedAt           *time.Time
	ReplacedBySessionID *uint
	IP                  string `gorm:"size:45"`
	UserAgent           string `gorm:"size:255"`
}

// AdminAuditLog registra eventos de seguranca e administracao.
type AdminAuditLog struct {
	ID           uint      `gorm:"primaryKey"`
	CreatedAt    time.Time `gorm:"index"`
	AdminUserID  *uint     `gorm:"index"`
	Action       string    `gorm:"size:60;not null;index"`
	TargetType   string    `gorm:"size:60"`
	TargetID     string    `gorm:"size:100"`
	Status       string    `gorm:"size:20;not null;index"`
	IP           string    `gorm:"size:45"`
	UserAgent    string    `gorm:"size:255"`
	MetadataJSON string    `gorm:"type:text"`
}
