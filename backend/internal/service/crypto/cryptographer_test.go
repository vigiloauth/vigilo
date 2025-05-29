package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
)

func TestCryptographer_HashString(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		plainStr        string
	}{
		{
			name:            "Valid Hash",
			wantErr:         false,
			expectedErrCode: "",
			plainStr:        "testString",
		},
		{
			name:            "Empty String",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeHashingFailed],
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewCryptographer()
			hashedStr, err := sut.HashString(test.plainStr)

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
				assert.Empty(t, hashedStr, "Expected empty hashed string on error")
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotEmpty(t, hashedStr, "Expected non-empty hashed string")
				assert.NotEqual(t, test.plainStr, hashedStr, "Hashed string should not match the plain string")
			}
		})
	}
}
