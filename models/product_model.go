package models

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

const ProductTableName = "products"

type Product struct {
	RowNo        uint64    `json:"row_no,omitempty" form:"-"`
	ID           uint64    `json:"id,string" form:"-"`
	CompanyID    uint64    `json:"-" form:"-"`
	CategoryID   *uint64   `json:"category_id" form:"category_id"`
	CategoryName *string   `json:"category_name" form:"-"`
	Name         string    `json:"name" form:"name"`
	Code         string    `json:"code" form:"code"`
	UOM          string    `json:"uom" form:"uom"`
	MinimumStock uint64    `json:"minimum_stock" form:"minimum_stock"`
	Stock        uint64    `json:"stock" form:"stock"`
	BasePrice    uint64    `json:"base_price" form:"base_price"`
	SellingPrice uint64    `json:"selling_price" form:"selling_price"`
	Weight       uint64    `json:"weight" form:"weight"`
	RackPosition string    `json:"rack_position" form:"rack_position"`
	CreatedBy    uint64    `json:"-" form:"-"`
	CreatedAt    time.Time `json:"-" form:"-"`
	UpdatedBy    uint64    `json:"-" form:"-"`
	UpdatedAt    time.Time `json:"-" form:"-"`
}

func (q *Product) Validate() error {
	if q.CategoryID != nil && *q.CategoryID == 0 {
		q.CategoryID = nil
	}
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Code = strings.TrimSpace(q.Code); q.Code == "" {
		return errors.New("code: is required")
	}
	q.UOM = strings.TrimSpace(q.UOM)
	q.RackPosition = strings.TrimSpace(q.RackPosition)
	return nil
}

type ProductFilter struct {
	ProductIDs,
	ProductCategoryIDs,
	CompanyIDs []uint64
	Keyword,
	PaginationURL string
	Limit,
	Page int64
	UrlValues url.Values
}

type ProductFilterOption func(q *ProductFilter)

func NewProductFilter(options ...ProductFilterOption) *ProductFilter {
	filter := &ProductFilter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func ProductWithProductIDs(productIDs ...uint64) ProductFilterOption {
	return func(q *ProductFilter) {
		q.ProductIDs = productIDs
	}
}

func ProductWithProductCategoryIDs(productCategoryIDs ...uint64) ProductFilterOption {
	return func(q *ProductFilter) {
		q.ProductCategoryIDs = productCategoryIDs
	}
}

func ProductWithCompanyIDs(companyIDs ...uint64) ProductFilterOption {
	return func(q *ProductFilter) {
		q.CompanyIDs = companyIDs
	}
}

func ProductWithKeyword(keyword string) ProductFilterOption {
	return func(q *ProductFilter) {
		q.Keyword = keyword
	}
}

func ProductWithPaginationURL(paginationURL string) ProductFilterOption {
	return func(q *ProductFilter) {
		q.PaginationURL = paginationURL
	}
}

func ProductWithLimit(limit int64) ProductFilterOption {
	return func(q *ProductFilter) {
		q.Limit = limit
	}
}

func ProductWithPage(page int64) ProductFilterOption {
	return func(q *ProductFilter) {
		q.Page = page
	}
}

func ProductWithUrlValues(urlValues url.Values) ProductFilterOption {
	return func(q *ProductFilter) {
		q.UrlValues = urlValues
	}
}

var ErrUniqueProductNameViolation = errors.New("name: already exists")
var ErrUniqueProductCodeViolation = errors.New("code: already exists")
