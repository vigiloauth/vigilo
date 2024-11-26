package load_tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/users"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

func setupEnvironment() (*sync.WaitGroup, *http.Client, string, int) {
	numRequests := 400
	timeoutDuration := 15 * time.Second
	port := "8080"
	startVigiloIdentityServer(port)

	var wg sync.WaitGroup
	wg.Add(numRequests)

	client := &http.Client{Timeout: timeoutDuration}
	url := "http://localhost:" + port + users.UserEndpoints.Registration

	return &wg, client, url, numRequests
}

func TestUserHandler_RegisterUser(t *testing.T) {
	waitGroup, client, url, numRequests := setupEnvironment()
	startTime := time.Now()

	var errors []error
	for i := 0; i < numRequests; i++ {
		go func() {
			err := sendRegistrationRequest(client, url, waitGroup)
			if err != nil {
				errors = append(errors, err)
			}
		}()
	}

	waitGroup.Wait()
	outputResults(startTime, numRequests, errors, t)
}

func sendRegistrationRequest(client *http.Client, url string, waitGroup *sync.WaitGroup) error {
	defer waitGroup.Done()

	payload, err := createRegistrationRequest()
	if err != nil {
		return fmt.Errorf("error marshalling registration request: %v", err)
	}

	req, err := createHttpRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("error creating registration request: %v", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}

	defer closeResponseBody(res.Body)

	_, err = io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	return nil
}

func createRegistrationRequest() ([]byte, error) {
	registrationRequest := users.NewUserRegistrationRequest(users.TestConstants.Username, users.TestConstants.Email, users.TestConstants.Password)
	payload, err := json.Marshal(registrationRequest)
	if err != nil {
		return nil, fmt.Errorf("error marshalling registration request: %w", err)
	}

	return payload, nil
}

func startVigiloIdentityServer(port string) {
	vigiloServer := server.NewVigiloIdentityServer(port)
	go vigiloServer.Start()
	time.Sleep(5 * time.Second)
}

func createHttpRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func closeResponseBody(body io.ReadCloser) {
	if err := body.Close(); err != nil {
		fmt.Println("Error closing response body:", err)
	}
}

func outputResults(startTime time.Time, numRequests int, errors []error, t *testing.T) {
	if len(errors) > 0 {
		for _, err := range errors {
			t.Errorf("Error during test: %v", err)
		}
		t.Fatalf("Test failed due to errors")
	}

	duration := time.Since(startTime)
	requestsPerSecond := float64(numRequests) / duration.Seconds()
	fmt.Printf("Load test completed in %v with %.2f requests per second\n", duration, requestsPerSecond)
}
