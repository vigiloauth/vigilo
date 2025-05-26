package types

type TokenType string

const (
	RefreshTokenType TokenType = "refresh"
	AccessTokenType  TokenType = "access"
)
