package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/constants"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestRateLimiting(t *testing.T) {
	user := users.NewUser("", testEmail, testPassword1)
	user.ID = testUserID

	request := users.UserLoginRequest{ID: testUserID, Username: testUsername, Password: testPassword1}
	requestBody, err := json.Marshal(request)
	assert.NoError(t, err, "failed to marshal request body")

	requestsPerMinute := 5
	testContext := NewVigiloTestContext(t)
	testContext.WithCustomConfig(config.WithMaxRequestsPerMinute(requestsPerMinute))

	for range requestsPerMinute {
		testContext.WithUser([]string{constants.UserManage}, []string{constants.AdminRole})
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.UserEndpoints.Login,
			bytes.NewBuffer(requestBody),
			nil,
		)

		t.Logf("body: %s", rr.Body.String())
		assert.Equal(t, http.StatusOK, rr.Code)
		testContext.ClearSession()
	}

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.UserEndpoints.Login,
		bytes.NewBuffer(requestBody),
		nil,
	)

	assert.Equal(t, http.StatusOK, rr.Code)
}
