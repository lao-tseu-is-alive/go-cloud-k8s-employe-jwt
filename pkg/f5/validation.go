package f5

import (
	"fmt"
	"regexp"
)

func ValidateLogin(login string) error {
	if len(login) < 3 || len(login) > 50 {
		return fmt.Errorf("login must be between 3 and 50 characters")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(login) {
		return fmt.Errorf("login contains invalid characters")
	}
	return nil
}

func ValidatePasswordHash(hash string) error {
	if len(hash) != 64 || !regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(hash) {
		return fmt.Errorf("invalid SHA-256 hash format")
	}
	return nil
}
