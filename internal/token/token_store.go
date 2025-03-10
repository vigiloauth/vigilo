package token

import "time"

type TokenStore interface {
	AddToken(token string, email string, expiration time.Time)
	IsTokenBlacklisted(token string) bool
	GetToken(token string, email string) (*TokenData, error)
	DeleteToken(token string) error
}

type TokenData struct {
	Token     string
	Email     string
	ExpiresAt time.Time
}
