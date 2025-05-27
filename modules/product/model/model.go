package model

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

const (
	StockTypeLimited int = iota
	StockTypeUnlimited
)

const (
	DiscountTypePercentage int = iota
	DiscountTypeAmount
)

type (
	Product struct {
		RowNo         uint64    `json:"row_no,omitempty"`
		ID            string    `json:"id"`
		CompanyID     string    `json:"-"`
		CategoryID    *string   `json:"category_id"`
		Name          string    `json:"name"`
		Code          string    `json:"code"`
		UOM           string    `json:"uom"`
		StockType     int       `json:"stock_type"`
		MinimumStock  int64     `json:"minimum_stock"`
		Stock         int64     `json:"stock"`
		PurchasePrice int64     `json:"purchase_price"`
		SellingPrice  int64     `json:"selling_price"`
		Weight        int64     `json:"weight"`
		DiscountType  int       `json:"discount_type"`
		DiscountValue int64     `json:"discount_value"`
		RackPosition  string    `json:"rack_position"`
		CreatedBy     string    `json:"-"`
		CreatedAt     time.Time `json:"-"`
		UpdatedBy     string    `json:"-"`
		UpdatedAt     time.Time `json:"-"`
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
	ErrUniqueCodeViolation = errors.New("code: already exists")
)

func (q *Product) Validate() error {
	if q.Name = strings.TrimSpace(q.Name); q.Name == "" {
		return errors.New("name: is required")
	}
	if q.Code = strings.TrimSpace(q.Code); q.Code == "" {
		return errors.New("code: is required")
	}
	q.UOM = strings.TrimSpace(q.UOM)
	if q.StockType != StockTypeLimited &&
		q.StockType != StockTypeUnlimited {
		return errors.New("stock_type: should be either 0 (limited) or 1 (unlimited)")
	}
	if q.MinimumStock < 0 {
		return errors.New("minimum_stock: requires a positive integer")
	}
	if q.Stock < 0 {
		return errors.New("stock: requires a positive integer")
	}
	if q.PurchasePrice < 0 {
		return errors.New("purchase_price: requires a positive integer")
	}
	if q.SellingPrice < 0 {
		return errors.New("selling_price: requires a positive integer")
	}
	if q.Weight < 0 {
		return errors.New("weight: requires a positive integer")
	}
	if q.DiscountType != DiscountTypePercentage &&
		q.DiscountType != DiscountTypeAmount {
		return errors.New("stock_type: should be either 0 (percentage) or 1 (amount)")
	}
	if q.DiscountValue < 0 {
		return errors.New("discount_value: requires a positive integer")
	}
	if q.DiscountType == DiscountTypePercentage &&
		q.DiscountValue > 100 {
		return errors.New("discount_value: exceeded maximum value (100)")
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
