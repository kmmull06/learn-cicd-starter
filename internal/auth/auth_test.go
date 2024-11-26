package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey testapikey123")

	apiKey, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if apiKey != "testapikey123" {
		t.Fatalf("Expected API key 'testapikey123', got %v", apiKey)
	}
}

func TestGetAPIKey_Error_NoAuthHeader(t *testing.T) {
	headers := http.Header{}

	apiKey, err := GetAPIKey(headers)

	if err == nil {
		t.Fatalf("Expected error, got none")
	}

	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("Expected error '%v', got '%v'", ErrNoAuthHeaderIncluded, err)
	}

	if apiKey != "" {
		t.Fatalf("Expected empty API key, got %v", apiKey)
	}
}

func TestGetAPIKey_Error_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "InvalidHeaderFormat")

	apiKey, err := GetAPIKey(headers)

	if err == nil {
		t.Fatalf("Expected error, got none")
	}

	expectedErr := "malformed authorization header"
	if err.Error() != expectedErr {
		t.Fatalf("Expected error '%v', got '%v'", expectedErr, err)
	}

	if apiKey != "" {
		t.Fatalf("Expected empty API key, got %v", apiKey)
	}
}
