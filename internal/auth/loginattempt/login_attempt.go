package auth

import "time"

const maxStoredLoginAttempts = 100

type LoginAttempt struct {
	UserID          string
	IPAddress       string
	Timestamp       time.Time
	RequestMetadata string
	Details         string
	UserAgent       string
	FailedAttempts  int
}
