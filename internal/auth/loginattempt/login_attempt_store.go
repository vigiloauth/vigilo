package auth

type LoginAttemptStore interface {
	SaveLoginAttempt(attempt *LoginAttempt)
	GetLoginAttempts(userID string) []*LoginAttempt
}
