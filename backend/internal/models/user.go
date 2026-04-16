package models

import "gorm.io/gorm"

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
