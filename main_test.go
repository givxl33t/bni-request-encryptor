package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEncryptDecryptEndpoints(t *testing.T) {
	handler := newHandler()
	secretKey := "0123456789abcdef0123456789abcdef"
	payload := `{"type":"createbilling","client_id":"000","trx_id":"INV-0001","trx_amount":"1000","billing_type":"c","customer_name":"Test Customer"}`
	encryptBody, err := json.Marshal(encryptRequest{
		ClientID:  "000",
		SecretKey: secretKey,
		Payload:   json.RawMessage(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	encryptRequest := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", bytes.NewReader(encryptBody))
	encryptResponse := httptest.NewRecorder()
	handler.ServeHTTP(encryptResponse, encryptRequest)
	if encryptResponse.Code != http.StatusOK {
		t.Fatalf("encrypt status = %d, want %d", encryptResponse.Code, http.StatusOK)
	}

	var encrypted struct {
		Encrypted string `json:"encrypted"`
	}
	if err := json.Unmarshal(encryptResponse.Body.Bytes(), &encrypted); err != nil {
		t.Fatal(err)
	}
	if encrypted.Encrypted == "" {
		t.Fatal("encrypt response has an empty encrypted value")
	}

	decryptBody, err := json.Marshal(map[string]string{
		"client_id":  "000",
		"secret_key": secretKey,
		"encrypted":  encrypted.Encrypted,
	})
	if err != nil {
		t.Fatal(err)
	}
	decryptRequest := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", bytes.NewReader(decryptBody))
	decryptResponse := httptest.NewRecorder()
	handler.ServeHTTP(decryptResponse, decryptRequest)
	if decryptResponse.Code != http.StatusOK {
		t.Fatalf("decrypt status = %d, want %d: %s", decryptResponse.Code, http.StatusOK, decryptResponse.Body.String())
	}

	var decrypted struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(decryptResponse.Body.Bytes(), &decrypted); err != nil {
		t.Fatal(err)
	}
	if decrypted.Payload != payload {
		t.Fatalf("decrypted payload = %q", decrypted.Payload)
	}
}

func TestEncryptRejectsMissingSecretKey(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", bytes.NewBufferString(`{"client_id":"000","payload":{}}`))
	response := httptest.NewRecorder()
	newHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestEncryptAcceptsDocumentedOperations(t *testing.T) {
	secretKey := "0123456789abcdef0123456789abcdef"
	payloads := []string{
		`{"type":"createbilling","client_id":"000","trx_id":"INV-0001","trx_amount":"1000","billing_type":"c","customer_name":"Test Customer"}`,
		`{"type":"createbillingsms","client_id":"000","trx_id":"INV-0002","trx_amount":"1000","billing_type":"c","customer_name":"Test Customer"}`,
		`{"type":"inquirybilling","client_id":"000","trx_id":"INV-0001"}`,
		`{"type":"updatebilling","client_id":"000","trx_id":"INV-0001","trx_amount":"1000","billing_type":"c","customer_name":"Test Customer"}`,
	}
	for _, payload := range payloads {
		response := performEncryptRequest(t, "000", secretKey, payload)
		if response.Code != http.StatusOK {
			t.Errorf("payload %s: status = %d, want %d: %s", payload, response.Code, http.StatusOK, response.Body.String())
		}
	}
}

func TestEncryptRejectsInvalidBNIPayloads(t *testing.T) {
	secretKey := "0123456789abcdef0123456789abcdef"
	invalidPayloads := []struct {
		name    string
		payload string
	}{
		{"missing required amount", `{"type":"createbilling","client_id":"000","trx_id":"INV-0001","billing_type":"c","customer_name":"Test"}`},
		{"fractional amount", `{"type":"createbilling","client_id":"000","trx_id":"INV-0001","trx_amount":"10.5","billing_type":"c","customer_name":"Test"}`},
		{"invalid billing type", `{"type":"createbilling","client_id":"000","trx_id":"INV-0001","trx_amount":"10","billing_type":"z","customer_name":"Test"}`},
		{"open payment amount must be zero", `{"type":"createbilling","client_id":"000","trx_id":"INV-0001","trx_amount":"10","billing_type":"o","customer_name":"Test"}`},
		{"sms billing must be fixed", `{"type":"createbillingsms","client_id":"000","trx_id":"INV-0001","trx_amount":"0","billing_type":"o","customer_name":"Test"}`},
		{"invalid email", `{"type":"createbilling","client_id":"000","trx_id":"INV-0001","trx_amount":"10","billing_type":"c","customer_name":"Test","customer_email":"not-an-email"}`},
		{"invalid phone", `{"type":"createbilling","client_id":"000","trx_id":"INV-0001","trx_amount":"10","billing_type":"c","customer_name":"Test","customer_phone":"555-0100"}`},
		{"invalid virtual account", `{"type":"createbilling","client_id":"000","trx_id":"INV-0001","trx_amount":"10","billing_type":"c","customer_name":"Test","virtual_account":"123"}`},
		{"invalid expiry", `{"type":"createbilling","client_id":"000","trx_id":"INV-0001","trx_amount":"10","billing_type":"c","customer_name":"Test","datetime_expired":"tomorrow"}`},
		{"credential mismatch", `{"type":"inquirybilling","client_id":"001","trx_id":"INV-0001"}`},
		{"unexpected field", `{"type":"inquirybilling","client_id":"000","trx_id":"INV-0001","trx_amount":"10"}`},
		{"unsupported operation", `{"type":"deletebilling","client_id":"000","trx_id":"INV-0001"}`},
	}
	for _, testCase := range invalidPayloads {
		t.Run(testCase.name, func(t *testing.T) {
			response := performEncryptRequest(t, "000", secretKey, testCase.payload)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
			}
		})
	}
}

func TestEncryptRejectsMalformedSecretKey(t *testing.T) {
	payload := `{"type":"inquirybilling","client_id":"000","trx_id":"INV-0001"}`
	response := performEncryptRequest(t, "000", "not-a-bni-key", payload)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestSwaggerEndpoints(t *testing.T) {
	handler := newHandler()

	uiRequest := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	uiResponse := httptest.NewRecorder()
	handler.ServeHTTP(uiResponse, uiRequest)
	if uiResponse.Code != http.StatusOK {
		t.Fatalf("Swagger UI status = %d, want %d", uiResponse.Code, http.StatusOK)
	}
	if got := uiResponse.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Swagger UI content type = %q", got)
	}
	if !bytes.Contains(uiResponse.Body.Bytes(), []byte("SwaggerUIBundle")) || !bytes.Contains(uiResponse.Body.Bytes(), []byte("/swagger.yaml")) {
		t.Fatal("Swagger UI does not reference Swagger UI assets and the OpenAPI document")
	}

	documentRequest := httptest.NewRequest(http.MethodGet, "/swagger.yaml", nil)
	documentResponse := httptest.NewRecorder()
	handler.ServeHTTP(documentResponse, documentRequest)
	if documentResponse.Code != http.StatusOK {
		t.Fatalf("OpenAPI document status = %d, want %d", documentResponse.Code, http.StatusOK)
	}
	if got := documentResponse.Header().Get("Content-Type"); got != "application/yaml; charset=utf-8" {
		t.Fatalf("OpenAPI document content type = %q", got)
	}
	if !bytes.Contains(documentResponse.Body.Bytes(), []byte("openapi: 3.0.3")) {
		t.Fatal("OpenAPI document response is missing the specification")
	}
}

func performEncryptRequest(t *testing.T, clientID string, secretKey string, payload string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(encryptRequest{
		ClientID:  clientID,
		SecretKey: secretKey,
		Payload:   json.RawMessage(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/encrypt", bytes.NewReader(body))
	response := httptest.NewRecorder()
	newHandler().ServeHTTP(response, request)
	return response
}
