package main

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	bniEnc "bni-request-encryptor/bniEnc"
)

const maxRequestBodySize = 1 << 20

//go:embed swagger.yaml
var swaggerDocument []byte

const swaggerUIHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>BNI Request Encryptor API</title>
	<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui.css">
</head>
<body>
	<div id="swagger-ui"></div>
	<script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
	<script>
		window.onload = () => SwaggerUIBundle({
			url: "/swagger.yaml",
			dom_id: "#swagger-ui",
			deepLinking: true,
			presets: [SwaggerUIBundle.presets.apis],
			layout: "BaseLayout"
		});
	</script>
</body>
</html>`

type api struct{}

type encryptRequest struct {
	ClientID  string          `json:"client_id"`
	SecretKey string          `json:"secret_key"`
	Payload   json.RawMessage `json:"payload"`
}

type decryptRequest struct {
	ClientID  string `json:"client_id"`
	SecretKey string `json:"secret_key"`
	Encrypted string `json:"encrypted"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           newHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func newHandler() http.Handler {
	handler := api{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/encrypt", handler.encrypt)
	mux.HandleFunc("/api/v1/decrypt", handler.decrypt)
	mux.HandleFunc("/healthz", handler.health)
	mux.HandleFunc("/swagger", handler.swaggerUI)
	mux.HandleFunc("/swagger.yaml", handler.swaggerDocument)
	return mux
}

func (api) encrypt(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body encryptRequest
	if err := decodeRequest(response, request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if err := validateEncryptRequest(body); err != nil {
		writeError(response, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(response, http.StatusOK, map[string]string{
		"encrypted": bniEnc.Encrypt(string(body.Payload), body.ClientID, body.SecretKey),
	})
}

func (api) decrypt(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body decryptRequest
	if err := decodeRequest(response, request, &body); err != nil {
		writeError(response, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if err := validateCredentials(body.ClientID, body.SecretKey); err != nil {
		writeError(response, http.StatusBadRequest, err.Error())
		return
	}
	if body.Encrypted == "" {
		writeError(response, http.StatusBadRequest, "encrypted is required")
		return
	}

	payload, err := bniEnc.Decrypt(body.Encrypted, body.ClientID, body.SecretKey)
	if err != nil {
		writeError(response, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"payload": payload})
}

func (api) health(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (api) swaggerUI(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(response, swaggerUIHTML)
}

func (api) swaggerDocument(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	response.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(swaggerDocument)
}

func decodeRequest(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBodySize)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func validateEncryptRequest(body encryptRequest) error {
	if err := validateCredentials(body.ClientID, body.SecretKey); err != nil {
		return err
	}
	if len(body.Payload) == 0 {
		return errors.New("payload is required")
	}
	return validateBNIPayload(body.Payload, body.ClientID)
}

func validateCredentials(clientID string, secretKey string) error {
	if clientID == "" || utf8.RuneCountInString(clientID) > 5 {
		return errors.New("client_id is required and must be at most 5 characters")
	}
	if len(secretKey) != 32 {
		return errors.New("secret_key must contain exactly 32 hexadecimal characters")
	}
	if _, err := hex.DecodeString(secretKey); err != nil {
		return errors.New("secret_key must contain exactly 32 hexadecimal characters")
	}
	return nil
}

func validateBNIPayload(raw json.RawMessage, requestClientID string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return errors.New("payload must be a JSON object")
	}

	action, err := payloadString(fields, "type", true)
	if err != nil {
		return err
	}

	allowedFields := map[string]bool{
		"type": true, "client_id": true, "trx_id": true,
	}
	switch action {
	case "createbilling", "createbillingsms", "updatebilling":
		for _, field := range []string{
			"trx_amount", "billing_type", "customer_name", "customer_email",
			"customer_phone", "virtual_account", "datetime_expired", "description",
		} {
			allowedFields[field] = true
		}
	case "inquirybilling":
	default:
		return errors.New("payload.type must be createbilling, createbillingsms, inquirybilling, or updatebilling")
	}
	for field := range fields {
		if !allowedFields[field] {
			return errors.New("payload contains unsupported field: " + field)
		}
	}

	clientID, err := payloadString(fields, "client_id", true)
	if err != nil {
		return err
	}
	if utf8.RuneCountInString(clientID) > 5 {
		return errors.New("payload.client_id must be at most 5 characters")
	}
	if clientID != requestClientID {
		return errors.New("payload.client_id must match client_id")
	}
	trxID, err := payloadString(fields, "trx_id", true)
	if err != nil {
		return err
	}
	if utf8.RuneCountInString(trxID) > 30 {
		return errors.New("payload.trx_id must be at most 30 characters")
	}

	if action == "inquirybilling" {
		return nil
	}

	amount, err := payloadString(fields, "trx_amount", true)
	if err != nil {
		return err
	}
	if len(amount) > 14 || !isDigits(amount) {
		return errors.New("payload.trx_amount must be an integer string of at most 14 digits")
	}

	billingType, err := payloadString(fields, "billing_type", true)
	if err != nil {
		return err
	}
	if len(billingType) != 1 || !strings.Contains("ocimnx", billingType) {
		return errors.New("payload.billing_type must be one of o, c, i, m, n, or x")
	}
	if action == "createbillingsms" && billingType != "c" {
		return errors.New("payload.billing_type must be c for createbillingsms")
	}
	if action == "createbilling" && billingType == "o" && amount != "0" {
		return errors.New("payload.trx_amount must be 0 for open payment billing_type o")
	}

	customerName, err := payloadString(fields, "customer_name", true)
	if err != nil {
		return err
	}
	if utf8.RuneCountInString(customerName) > 255 {
		return errors.New("payload.customer_name must be at most 255 characters")
	}

	if email, err := payloadString(fields, "customer_email", false); err != nil {
		return err
	} else if email != "" {
		address, parseErr := mail.ParseAddress(email)
		if len(email) > 255 || parseErr != nil || address.Address != email {
			return errors.New("payload.customer_email must be a valid email address of at most 255 characters")
		}
	}

	if phone, err := payloadString(fields, "customer_phone", false); err != nil {
		return err
	} else if phone != "" && !isValidPhone(phone) {
		return errors.New("payload.customer_phone must use the +62 or 0-prefixed numeric format and be at most 15 characters")
	}

	if account, err := payloadString(fields, "virtual_account", false); err != nil {
		return err
	} else if account != "" && (len(account) != 16 || !isDigits(account)) {
		return errors.New("payload.virtual_account must contain exactly 16 digits")
	}

	if expiry, err := payloadString(fields, "datetime_expired", false); err != nil {
		return err
	} else if expiry != "" {
		if _, parseErr := time.Parse(time.RFC3339, expiry); parseErr != nil {
			return errors.New("payload.datetime_expired must be an ISO 8601 date-time with a timezone")
		}
	}

	if _, err := payloadString(fields, "description", false); err != nil {
		return err
	}
	return nil
}

func payloadString(fields map[string]json.RawMessage, name string, required bool) (string, error) {
	raw, exists := fields[name]
	if !exists {
		if required {
			return "", errors.New("payload." + name + " is required")
		}
		return "", nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", errors.New("payload." + name + " must be a string")
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", errors.New("payload." + name + " must be a string")
	}
	if required && value == "" {
		return "", errors.New("payload." + name + " is required")
	}
	return value, nil
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func isValidPhone(value string) bool {
	if len(value) > 15 {
		return false
	}
	if strings.HasPrefix(value, "+62") {
		return len(value) > 3 && isDigits(value[3:])
	}
	if strings.HasPrefix(value, "0") {
		return len(value) > 1 && isDigits(value[1:])
	}
	return false
}

func writeError(response http.ResponseWriter, status int, message string) {
	writeJSON(response, status, errorResponse{Error: message})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
