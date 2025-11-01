package models

import "strings"

// SignUpRequest captures user-supplied information for account registration.
type SignUpRequest struct {
	FirstName string `json:"first_name,omitempty" form:"first_name" validate:"omitempty,min=1,max=128,alphaunicode"`
	LastName  string `json:"last_name,omitempty" form:"last_name" validate:"omitempty,min=1,max=128,alphaunicode"`
	Username  string `json:"username" form:"username" validate:"required,min=3,max=64,alphanum"`
	Password  Secret `json:"password" form:"password" validate:"required,min=12"`
	Email     string `json:"email,omitempty" form:"email" validate:"omitempty,email,max=254"`
}

// Normalize trims and lowercases fields where appropriate to ensure consistent storage.
func (r *SignUpRequest) Normalize() {
	r.FirstName = strings.TrimSpace(r.FirstName)
	r.LastName = strings.TrimSpace(r.LastName)
	r.Username = strings.ToLower(strings.TrimSpace(r.Username))
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
}
