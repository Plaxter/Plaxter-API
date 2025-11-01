package models

import (
	"encoding/json"
	"errors"
)

// Secret wraps sensitive credential material to avoid accidental disclosure
// through logging or JSON encoding. Use Reveal when absolutely necessary.
type Secret string

// String redacts the secret when formatted with fmt.
func (s Secret) String() string {
	return "[REDACTED]"
}

// GoString redacts the secret during %#v formatting.
func (s Secret) GoString() string {
	return s.String()
}

// Reveal returns the raw secret value. Guard access carefully.
func (s Secret) Reveal() string {
	return string(s)
}

// MarshalJSON redacts the secret when emitting JSON.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"***redacted***"`), nil
}

// UnmarshalJSON parses a JSON string while ensuring the secret is not empty.
func (s *Secret) UnmarshalJSON(data []byte) error {
	var plaintext string
	if err := json.Unmarshal(data, &plaintext); err != nil {
		return err
	}

	if plaintext == "" {
		return errors.New("secret value must not be empty")
	}

	*s = Secret(plaintext)
	return nil
}

// LoginRequest carries authentication credentials supplied by a client.
type LoginRequest struct {
	Username string `json:"username" form:"username" validate:"required,min=3,max=64,alphanum"`
	Password Secret `json:"password" form:"password" validate:"required,min=12"`
}
