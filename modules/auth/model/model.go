package model

import (
	"encoding/base64"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/errors"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
)

type (
	LoginRequest struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	LoginResponse struct {
		IDToken   string                `json:"id_token"`
		ExpiredAt time.Time             `json:"expired_at"`
		Account   *accountModel.Account `json:"account"`
	}
)

var (
	ErrLoginFailed = errors.New(fiber.StatusBadRequest, "login failed")
)

func (q LoginRequest) DecodePassword() ([]byte, error) {
	return base64.StdEncoding.DecodeString(q.Password)
}
