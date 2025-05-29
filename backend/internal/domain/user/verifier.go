package domain

import "context"

type UserVerifier interface {
	// VerifyEmailAddress validates the verification code and marks the user's email as verified.
	//
	// Parameter:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- verificationCode string: The verification code to verify.
	//
	// Returns:
	//	- error: an error if validation fails, otherwise nil.
	VerifyEmailAddress(ctx context.Context, verificationCode string) error
}
