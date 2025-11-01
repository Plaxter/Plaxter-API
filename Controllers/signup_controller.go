package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	models "plaxterapi/Models"
	services "plaxterapi/Services"
)

const (
	defaultRequestTimeout = 5 * time.Second
	maxRequestBodyBytes   = 1 << 20 // 1 MiB
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{3,64}$`)

type SignUpController struct {
	users services.UserRegistrationService
}

func NewSignUpController(users services.UserRegistrationService) *SignUpController {
	return &SignUpController{users: users}
}

// Handle responds to POST /signup. It validates payloads, enforces sane limits,
// and delegates to the configured user registration service.
func (c *SignUpController) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
	defer cancel()

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	defer func() {
		// Ensure we exhaust the body to help connection reuse.
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}()

	var payload models.SignUpRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := ensureEOF(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "unexpected trailing data")
		return
	}

	payload.Normalize()
	if err := validateSignUpRequest(payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := c.users.RegisterUser(ctx, payload); err != nil {
		switch {
		case errors.Is(err, services.ErrUserAlreadyExists):
			writeError(w, http.StatusConflict, "account exists, please sign in")
		default:
			writeError(w, http.StatusInternalServerError, "signup unavailable")
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"message": "account created"})
}

func validateSignUpRequest(payload models.SignUpRequest) error {
	if !usernamePattern.MatchString(payload.Username) {
		return errors.New("username must be 3-64 characters and use letters, digits, or underscores")
	}

	if len(payload.Password.Reveal()) < 12 {
		return errors.New("password must be at least 12 characters")
	}

	if payload.Email != "" {
		if _, err := mail.ParseAddress(payload.Email); err != nil {
			return errors.New("invalid email address")
		}
	}

	// Limit provided names to avoid control characters.
	if err := validateName(payload.FirstName); err != nil {
		return err
	}
	if err := validateName(payload.LastName); err != nil {
		return err
	}

	return nil
}

func validateName(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 128 {
		return errors.New("names must be fewer than 128 characters")
	}
	if strings.ContainsAny(name, "<>{}\n\r\t") {
		return errors.New("names contain unsupported characters")
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing data")
		}
		return err
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
