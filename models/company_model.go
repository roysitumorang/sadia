package models

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Company struct {
	RowNo              uint64     `json:"row_no,omitempty"`
	ID                 uint64     `json:"id,string"`
	Name               string     `json:"name"`
	Slug               string     `json:"slug"`
	Status             uint8      `json:"status"`
	CreatedBy          uint64     `json:"-"`
	CreatedAt          time.Time  `json:"-"`
	UpdatedBy          uint64     `json:"-"`
	UpdatedAt          time.Time  `json:"-"`
	DeactivatedBy      *uint64    `json:"-"`
	DeactivatedAt      *time.Time `json:"-"`
	DeactivationReason *string    `json:"-"`
	SessionID          *uint64    `json:"session_id,string"`
}

type CompanyFilter struct {
	CompanyIDs []uint64
	StatusList []uint8
	Keyword,
	PaginationURL string
	Limit,
	Page int64
	UrlValues url.Values
}

type CompanyFilterOption func(q *CompanyFilter)

func NewCompanyFilter(options ...CompanyFilterOption) *CompanyFilter {
	filter := &CompanyFilter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func CompanyWithCompanyIDs(companyIDs ...uint64) CompanyFilterOption {
	return func(q *CompanyFilter) {
		q.CompanyIDs = companyIDs
	}
}

func CompanyWithStatusList(statusList ...uint8) CompanyFilterOption {
	return func(q *CompanyFilter) {
		q.StatusList = statusList
	}
}

func CompanyWithKeyword(keyword string) CompanyFilterOption {
	return func(q *CompanyFilter) {
		q.Keyword = keyword
	}
}

func CompanyWithPaginationURL(paginationURL string) CompanyFilterOption {
	return func(q *CompanyFilter) {
		q.PaginationURL = paginationURL
	}
}

func CompanyWithLimit(limit int64) CompanyFilterOption {
	return func(q *CompanyFilter) {
		q.Limit = limit
	}
}

func CompanyWithPage(page int64) CompanyFilterOption {
	return func(q *CompanyFilter) {
		q.Page = page
	}
}

func CompanyWithUrlValues(urlValues url.Values) CompanyFilterOption {
	return func(q *CompanyFilter) {
		q.UrlValues = urlValues
	}
}

type NewCompany struct {
	Name      string      `json:"name"`
	Slug      string      `json:"-"`
	Status    int8        `json:"-"`
	Owner     *NewAccount `json:"owner"`
	CreatedBy uint64      `json:"-"`
}

func (q *NewCompany) Validate() error {
	if q.Owner == nil {
		return errors.New("owner: is required")
	}
	q.Owner.AccountType = AccountTypeUser
	if err := q.Owner.Validate(); err != nil {
		return fmt.Errorf("owner.%s", err.Error())
	}
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	return nil
}

type CompanyDeactivation struct {
	Reason string `json:"reason"`
}

func (q *CompanyDeactivation) Validate() error {
	if q.Reason = strings.TrimSpace(q.Reason); q.Reason == "" {
		return errors.New("reason: is required")
	}
	return nil
}

type UpdateCompany struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (q *UpdateCompany) Validate() error {
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Slug = strings.TrimSpace(q.Slug); q.Slug == "" {
		return errors.New("slug: is required")
	}
	return nil
}

var ErrUniqueCompanySlugViolation = errors.New("slug: already exists")
