package model

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

type (
	Product struct {
		ID         string    `json:"id"`
		CompanyID  string    `json:"-"`
		CategoryID *string   `json:"category_id"`
		Name       string    `json:"name"`
		Slug       string    `json:"slug"`
		UOM        string    `json:"uom"`
		Stock      uint16    `json:"stock"`
		Price      uint      `json:"price"`
		CreatedBy  string    `json:"-"`
		CreatedAt  time.Time `json:"-"`
		UpdatedBy  string    `json:"-"`
		UpdatedAt  time.Time `json:"-"`
	}

	Filter struct {
		ProductIDs,
		ProductCategoryIDs,
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

func (q *Product) Validate() error {
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Slug = strings.TrimSpace(q.Slug); q.Slug == "" {
		return errors.New("slug: is required")
	}
	if q.UOM = strings.TrimSpace(q.UOM); q.UOM == "" {
		return errors.New("uom: is required")
	}
	return nil
}

func NewFilter(options ...FilterOption) *Filter {
	filter := &Filter{}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func WithProductIDs(productIDs ...string) FilterOption {
	return func(q *Filter) {
		q.ProductIDs = productIDs
	}
}

func WithProductCategoryIDs(productCategoryIDs ...string) FilterOption {
	return func(q *Filter) {
		q.ProductCategoryIDs = productCategoryIDs
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
