package models

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

const ProductCategoryTableName = "product_categories"

type ProductCategory struct {
	RowNo     uint64    `json:"row_no,omitempty" form:"-"`
	ID        uint64    `json:"id,string" form:"-"`
	CompanyID uint64    `json:"-" form:"-"`
	Name      string    `json:"name" form:"name"`
	Slug      string    `json:"slug" form:"slug"`
	CreatedBy uint64    `json:"-" form:"-"`
	CreatedAt time.Time `json:"-" form:"-"`
	UpdatedBy uint64    `json:"-" form:"-"`
	UpdatedAt time.Time `json:"-" form:"-"`
}

func (q *ProductCategory) Validate() error {
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	q.Slug = strings.TrimSpace(q.Slug)
	if q.Slug == "" {
		q.Slug = strings.ToLower(q.Name)
	}
	q.Slug = UsernameRegex.ReplaceAllString(q.Slug, "")
	return nil
}

type ProductCategoryFilter struct {
	ProductCategoryIDs,
	CompanyIDs []uint64
	Keyword,
	PaginationURL string
	Limit,
	Page int64
	UrlValues url.Values
}

type ProductCategoryFilterOption func(q *ProductCategoryFilter)

func NewProductCategoryFilter(options ...ProductCategoryFilterOption) *ProductCategoryFilter {
	filter := &ProductCategoryFilter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func ProductCategoryWithProductCategoryIDs(productCategoryIDs ...uint64) ProductCategoryFilterOption {
	return func(q *ProductCategoryFilter) {
		q.ProductCategoryIDs = productCategoryIDs
	}
}

func ProductCategoryWithCompanyIDs(companyIDs ...uint64) ProductCategoryFilterOption {
	return func(q *ProductCategoryFilter) {
		q.CompanyIDs = companyIDs
	}
}

func ProductCategoryWithKeyword(keyword string) ProductCategoryFilterOption {
	return func(q *ProductCategoryFilter) {
		q.Keyword = keyword
	}
}

func ProductCategoryWithPaginationURL(paginationURL string) ProductCategoryFilterOption {
	return func(q *ProductCategoryFilter) {
		q.PaginationURL = paginationURL
	}
}

func ProductCategoryWithLimit(limit int64) ProductCategoryFilterOption {
	return func(q *ProductCategoryFilter) {
		q.Limit = limit
	}
}

func ProductCategoryWithPage(page int64) ProductCategoryFilterOption {
	return func(q *ProductCategoryFilter) {
		q.Page = page
	}
}

func ProductCategoryWithUrlValues(urlValues url.Values) ProductCategoryFilterOption {
	return func(q *ProductCategoryFilter) {
		q.UrlValues = urlValues
	}
}

var ErrUniqueProductCategoryNameViolation = errors.New("name: already exists")
var ErrUniqueProductCategorySlugViolation = errors.New("slug: already exists")
