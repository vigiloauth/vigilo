package token

import "time"

type TokenBlacklist interface {
	AddToken(token string, expiration time.Time)
	IsTokenBlacklisted(token string) bool
}
