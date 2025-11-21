package model

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

type (
	Product struct {
		RowNo        uint64    `json:"row_no,omitempty" form:"-"`
		ID           int64     `json:"id" form:"-"`
		CompanyID    int64     `json:"-" form:"-"`
		CategoryID   *int64    `json:"category_id" form:"category_id"`
		CategoryName *string   `json:"category_name" form:"-"`
		Name         string    `json:"name" form:"name"`
		Code         string    `json:"code" form:"code"`
		UOM          string    `json:"uom" form:"uom"`
		MinimumStock int64     `json:"minimum_stock" form:"minimum_stock"`
		Stock        int64     `json:"stock" form:"stock"`
		BasePrice    int64     `json:"base_price" form:"base_price"`
		SellingPrice int64     `json:"selling_price" form:"selling_price"`
		Weight       int64     `json:"weight" form:"weight"`
		RackPosition string    `json:"rack_position" form:"rack_position"`
		CreatedBy    int64     `json:"-" form:"-"`
		CreatedAt    time.Time `json:"-" form:"-"`
		UpdatedBy    int64     `json:"-" form:"-"`
		UpdatedAt    time.Time `json:"-" form:"-"`
	}

	Filter struct {
		ProductIDs,
		ProductCategoryIDs,
		CompanyIDs []int64
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
	ErrUniqueCodeViolation = errors.New("code: already exists")
)

func (q *Product) Validate() error {
	if q.CategoryID != nil && *q.CategoryID < 1 {
		q.CategoryID = nil
	}
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Code = strings.TrimSpace(q.Code); q.Code == "" {
		return errors.New("code: is required")
	}
	q.UOM = strings.TrimSpace(q.UOM)
	if q.MinimumStock < 0 {
		return errors.New("minimum_stock: requires a positive integer")
	}
	if q.Stock < 0 {
		return errors.New("stock: requires a positive integer")
	}
	if q.BasePrice < 0 {
		return errors.New("base_price: requires a positive integer")
	}
	if q.SellingPrice < 0 {
		return errors.New("selling_price: requires a positive integer")
	}
	if q.Weight < 0 {
		return errors.New("weight: requires a positive integer")
	}
	q.RackPosition = strings.TrimSpace(q.RackPosition)
	return nil
}

func NewFilter(options ...FilterOption) *Filter {
	filter := &Filter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func WithProductIDs(productIDs ...int64) FilterOption {
	return func(q *Filter) {
		q.ProductIDs = productIDs
	}
}

func WithProductCategoryIDs(productCategoryIDs ...int64) FilterOption {
	return func(q *Filter) {
		q.ProductCategoryIDs = productCategoryIDs
	}
}

func WithCompanyIDs(companyIDs ...int64) FilterOption {
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
