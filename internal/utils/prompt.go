package utils

import (
	"errors"
	"fmt"

	"github.com/ncruces/zenity"
)

func PromptForPassword(title string) (string, error) {
	if _, pwd, err := zenity.Password(
		zenity.Title(title),
		zenity.OKLabel("Unlock"),
	); err == nil {
		return pwd, nil
	} else if errors.Is(err, zenity.ErrCanceled) {
		return "", fmt.Errorf("user canceled prompt for password")
	}
	return "", fmt.Errorf("failed to get password from user")
}
