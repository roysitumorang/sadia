package models

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

const (
	CurrentAdmin = "current_admin"
	CurrentUser  = "current_user"
	CurrentJwt   = "current_jwt"
)

const (
	AccountTypeAdmin uint8 = iota
	AccountTypeUser
)

const (
	StatusUnconfirmed int8 = iota
	StatusConfirmed
	StatusDeactivated int8 = -1
)

type (
	Pagination struct {
		Links struct {
			First    string `json:"first" example:"http://localhost:19000/v1/cities?limit=1&search=Tangerang"`
			Previous string `json:"previous" example:"http://localhost:19000/v1/cities?limit=1&search=Tangerang"`
			Current  string `json:"current" example:"http://localhost:19000/v1/cities?limit=1&page=2&search=Tangerang"`
			Next     string `json:"next" example:"http://localhost:19000/v1/cities?limit=1&page=3&search=Tangerang"`
		} `json:"links"`
		Info struct {
			Limit int64 `json:"limit" example:"1"`
			Pages int64 `json:"pages" example:"3"`
			Total int64 `json:"total" example:"3"`
		} `json:"info"`
	}

	NewAccount struct {
		AccountType uint8   `json:"account_type"`
		Name        string  `json:"name"`
		Username    string  `json:"username"`
		Email       *string `json:"email"`
		Phone       *string `json:"phone"`
		CreatedBy   *string `json:"-"`
	}

	Message struct {
		Action string `json:"action"`
		ID     string `json:"id"`
	}
)

var (
	MapLimits        = map[int]int{1: 1, 10: 1, 25: 1, 50: 1, 100: 1}
	Limits           = []int{1, 10, 25, 50, 100}
	PhoneNumberRegex = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
)

func (q *NewAccount) Validate() error {
	if q.AccountType != AccountTypeAdmin &&
		q.AccountType != AccountTypeUser {
		return fmt.Errorf(
			"account_type: should be either %d or %d",
			AccountTypeAdmin,
			AccountTypeUser,
		)
	}
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Username = strings.ToLower(strings.TrimSpace(q.Username)); q.Username == "" {
		return errors.New("username: is required")
	}
	if q.Email != nil {
		if *q.Email = strings.ToLower(strings.TrimSpace(*q.Email)); *q.Email != "" {
			if _, err := mail.ParseAddress(*q.Email); err != nil {
				return errors.New("email: invalid address")
			}
		} else {
			q.Email = nil
		}
	}
	if q.Phone != nil {
		if *q.Phone = strings.TrimSpace(*q.Phone); *q.Phone != "" {
			phone, err := phonenumbers.Parse(*q.Phone, "ID")
			if err != nil {
				return err
			}
			*q.Phone = phonenumbers.Format(phone, phonenumbers.E164)
			if PhoneNumberRegex.Find([]byte(*q.Phone)) == nil {
				return errors.New("phone: invalid number")
			}
		} else {
			q.Phone = nil
		}
	}
	if q.Email == nil && q.Phone == nil {
		return errors.New("email: at least a valid email or phone number required")
	}
	return nil
}
