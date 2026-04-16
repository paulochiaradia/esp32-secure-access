package models

import (
	"time"

	"gorm.io/gorm"
)

// Tabela de usuários autorizados
type User struct {
	gorm.Model
	UID    string `gorm:"uniqueIndex"`
	Name   string
	Active bool
}

// Tabela de logs para auditoria
type AccessLog struct {
	gorm.Model
	UID     string
	Status  string // "authorized" ou "denied"
	Message string
}

// Tabela de nonces utilizados para proteger contra replay attack.
type UsedNonce struct {
	gorm.Model
	UID       string    `gorm:"index:idx_uid_nonce,unique"`
	Nonce     string    `gorm:"index:idx_uid_nonce,unique"`
	ExpiresAt time.Time `gorm:"index"`
}
