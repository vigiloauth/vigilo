package domain

import (
	"sync"

	"github.com/vigiloauth/vigilo/internal/crypto"
)

type EmailRequest struct {
	Recipient         string
	EmailType         EmailType
	VerificationCode  string
	VerificationToken string
	BaseURL           string
	ID                string
	Retries           int
}

func NewEmailRequest(recipient, verificationCode, verificationToken string, emailType EmailType) *EmailRequest {
	return &EmailRequest{
		Recipient:         recipient,
		VerificationCode:  verificationCode,
		VerificationToken: verificationCode,
		EmailType:         emailType,
		ID:                crypto.GenerateUUID(),
		Retries:           0,
	}
}

type EmailType string

const (
	AccountVerification EmailType = "account_verification"
	AccountDeletion     EmailType = "account_deletion"
)

func (t EmailType) String() string {
	return "account_verification"
}

type EmailRetryQueue struct {
	mu       sync.Mutex
	requests []*EmailRequest
}

func (q *EmailRetryQueue) Add(request *EmailRequest) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.requests = append(q.requests, request)
}

func (q *EmailRetryQueue) Remove() *EmailRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.requests) == 0 {
		return nil
	}

	request := q.requests[0]
	q.requests = q.requests[1:]
	return request
}

func (q *EmailRetryQueue) IsEmpty() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.requests) == 0
}

func (q *EmailRetryQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.requests)
}
