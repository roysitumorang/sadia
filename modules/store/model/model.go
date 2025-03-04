package model

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/roysitumorang/sadia/models"
)

type (
	Store struct {
		RowNo            uint64    `json:"row_no,omitempty"`
		ID               string    `json:"id"`
		CompanyID        string    `json:"-"`
		Name             string    `json:"name"`
		Slug             string    `json:"slug"`
		CreatedBy        string    `json:"-"`
		CreatedAt        time.Time `json:"-"`
		UpdatedBy        string    `json:"-"`
		UpdatedAt        time.Time `json:"-"`
		CurrentSessionID *string   `json:"current_session_id"`
	}

	Filter struct {
		StoreIDs,
		CompanyIDs []string
		Keyword,
		PaginationURL string
		Limit,
		Page int64
		UrlValues url.Values
	}

	FilterOption func(q *Filter)
)

var (
	ErrUniqueNameViolation = errors.New("name: already exists")
	ErrUniqueSlugViolation = errors.New("slug: already exists")
)

func (q *Store) Validate() error {
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	q.Slug = strings.TrimSpace(q.Slug)
	if q.Slug == "" {
		q.Slug = strings.ToLower(q.Name)
	}
	q.Slug = models.UsernameRegex.ReplaceAllString(q.Slug, "")
	return nil
}

func NewFilter(options ...FilterOption) *Filter {
	filter := &Filter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func WithStoreIDs(storeIDs ...string) FilterOption {
	return func(q *Filter) {
		q.StoreIDs = storeIDs
	}
}

func WithCompanyIDs(companyIDs ...string) FilterOption {
	return func(q *Filter) {
		q.CompanyIDs = companyIDs
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
