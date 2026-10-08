package models

import (
	"errors"
	"fmt"
	"maps"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/coregx/coregex"
	"github.com/nyaruka/phonenumbers"
)

const Authenticated = "authenticated"
const CurrentAdmin = "current_admin"
const CurrentUser = "current_user"
const CurrentJwt = "current_jwt"
const UserID = "user_id"
const CurrentCompany = "current_company"
const CurrentSession = "current_session"

const (
	AccountTypeAdmin uint8 = iota
	AccountTypeUser
)

const (
	StatusUnconfirmed uint8 = iota
	StatusConfirmed
	StatusDeactivated
)

const TopicAccount = "account"
const TopicJwt = "jwt"
const TopicCompany = "company"
const TopicProductCategory = "product_category"
const TopicProduct = "product"
const TopicStore = "store"
const TopicSession = "session"
const TopicTransaction = "transaction"

type Pagination struct {
	Links struct {
		First    string `json:"first" example:"http://localhost:19000/v1/cities?limit=1&search=Tangerang"`
		Previous string `json:"previous" example:"http://localhost:19000/v1/cities?limit=1&search=Tangerang"`
		Current  string `json:"current" example:"http://localhost:19000/v1/cities?limit=1&page=2&search=Tangerang"`
		Next     string `json:"next" example:"http://localhost:19000/v1/cities?limit=1&page=3&search=Tangerang"`
		Last     string `json:"last" example:"http://localhost:19000/v1/cities?limit=1&page=4&search=Tangerang"`
	} `json:"links"`
	Info struct {
		Limit int64 `json:"limit" example:"1"`
		Page  int64 `json:"page" example:"1"`
		Pages int64 `json:"pages" example:"3"`
		Total int64 `json:"total" example:"3"`
	} `json:"info"`
}

func SetPagination(total, pages, limit, page int64, baseURL string, urlValues url.Values) (*Pagination, error) {
	var response Pagination
	var builder strings.Builder
	response.Info.Total = total
	response.Info.Page = page
	response.Info.Pages = pages
	response.Info.Limit = limit
	response.Links.First = baseURL
	response.Links.Current = baseURL
	if len(urlValues) > 0 {
		u := maps.Clone(urlValues)
		queryString, err := url.QueryUnescape(u.Encode())
		if err != nil {
			return nil, err
		}
		builder.Reset()
		_, _ = builder.WriteString(baseURL)
		_, _ = builder.WriteString("?")
		_, _ = builder.WriteString(queryString)
		response.Links.Current = builder.String()
		u.Del("page")
		if queryString, err = url.QueryUnescape(u.Encode()); err != nil {
			return nil, err
		}
		builder.Reset()
		_, _ = builder.WriteString(baseURL)
		_, _ = builder.WriteString("?")
		_, _ = builder.WriteString(queryString)
		response.Links.First = builder.String()
	}
	if n := pages - 1; page < n {
		u := maps.Clone(urlValues)
		u.Set("page", strconv.FormatInt(n, 10))
		queryString, err := url.QueryUnescape(u.Encode())
		if err != nil {
			return nil, err
		}
		builder.Reset()
		_, _ = builder.WriteString(baseURL)
		_, _ = builder.WriteString("?")
		_, _ = builder.WriteString(queryString)
		response.Links.Last = builder.String()
		u.Set("page", strconv.FormatInt(page+1, 10))
		if queryString, err = url.QueryUnescape(u.Encode()); err != nil {
			return nil, err
		}
		builder.Reset()
		_, _ = builder.WriteString(baseURL)
		_, _ = builder.WriteString("?")
		_, _ = builder.WriteString(queryString)
		response.Links.Next = builder.String()
	}
	if page > 0 {
		u := maps.Clone(urlValues)
		u.Set("page", strconv.FormatInt(page, 10))
		queryString, err := url.QueryUnescape(u.Encode())
		if err != nil {
			return nil, err
		}
		builder.Reset()
		_, _ = builder.WriteString(baseURL)
		_, _ = builder.WriteString("?")
		_, _ = builder.WriteString(queryString)
		response.Links.Current = builder.String()
		if page > 1 {
			u.Set("page", strconv.FormatInt(page-1, 10))
			if queryString, err = url.QueryUnescape(u.Encode()); err != nil {
				return nil, err
			}
			builder.Reset()
			_, _ = builder.WriteString(baseURL)
			_, _ = builder.WriteString("?")
			_, _ = builder.WriteString(queryString)
			response.Links.Previous = builder.String()
		}
	}
	return &response, nil
}

type NewAccount struct {
	AccountType uint8   `json:"account_type"`
	Name        string  `json:"name"`
	Username    string  `json:"username"`
	Email       *string `json:"email"`
	Phone       *string `json:"phone"`
	CreatedBy   *uint64 `json:"-"`
}

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

type Message struct {
	Action string `json:"action"`
	ID     string `json:"id"`
}

var MapLimits = map[int64]struct{}{
	10:  struct{}{},
	25:  struct{}{},
	50:  struct{}{},
	100: struct{}{},
}
var Limits = []int64{10, 25, 50, 100}
var PhoneNumberRegex = coregex.MustCompile(`^\+[1-9]\d{1,14}$`)
var UsernameRegex = coregex.MustCompile("[^a-z0-9]+")
var SliceTopics = []string{
	TopicAccount,
	TopicJwt,
	TopicCompany,
	TopicProductCategory,
	TopicProduct,
	TopicStore,
	TopicSession,
	TopicTransaction,
}
var MapTopics = map[string]struct{}{
	TopicAccount:         struct{}{},
	TopicJwt:             struct{}{},
	TopicCompany:         struct{}{},
	TopicProductCategory: struct{}{},
	TopicProduct:         struct{}{},
	TopicStore:           struct{}{},
	TopicSession:         struct{}{},
	TopicTransaction:     struct{}{},
}
