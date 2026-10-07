package model

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/roysitumorang/sadia/models"
)

type (
	Company struct {
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

	Filter struct {
		CompanyIDs []uint64
		StatusList []uint8
		Keyword,
		PaginationURL string
		Limit,
		Page int64
		UrlValues url.Values
	}

	FilterOption func(q *Filter)

	NewCompany struct {
		Name      string             `json:"name"`
		Slug      string             `json:"-"`
		Status    int8               `json:"-"`
		Owner     *models.NewAccount `json:"owner"`
		CreatedBy uint64             `json:"-"`
	}

	Deactivation struct {
		Reason string `json:"reason"`
	}

	UpdateCompany struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
)

var (
	ErrUniqueSlugViolation = errors.New("slug: already exists")
)

func NewFilter(options ...FilterOption) *Filter {
	filter := &Filter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func WithCompanyIDs(companyIDs ...uint64) FilterOption {
	return func(q *Filter) {
		q.CompanyIDs = companyIDs
	}
}

func WithStatusList(statusList ...uint8) FilterOption {
	return func(q *Filter) {
		q.StatusList = statusList
	}
}

func WithKeyword(keyword string) FilterOption {
	return func(q *Filter) {
		q.Keyword = keyword
	}
}

func WithPaginationURL(paginationURL string) FilterOption {
	return func(q *Filter) {
		q.PaginationURL = paginationURL
	}
}

func WithLimit(limit int64) FilterOption {
	return func(q *Filter) {
		q.Limit = limit
	}
}

func WithPage(page int64) FilterOption {
	return func(q *Filter) {
		q.Page = page
	}
}

func WithUrlValues(urlValues url.Values) FilterOption {
	return func(q *Filter) {
		q.UrlValues = urlValues
	}
}

func (q *NewCompany) Validate() error {
	if q.Owner == nil {
		return errors.New("owner: is required")
	}
	q.Owner.AccountType = models.AccountTypeUser
	if err := q.Owner.Validate(); err != nil {
		return fmt.Errorf("owner.%s", err.Error())
	}
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	return nil
}

func (q *Deactivation) Validate() error {
	if q.Reason = strings.TrimSpace(q.Reason); q.Reason == "" {
		return errors.New("reason: is required")
	}
	return nil
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
