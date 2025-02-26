package model

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/govalues/decimal"
	"github.com/roysitumorang/sadia/helper"
	productModel "github.com/roysitumorang/sadia/modules/product/model"
)

const (
	PaymentMethodCash uint8 = iota
	PaymentMethodBankTransfer
)

const (
	TableName         = "transactions"
	ReferenceNoFormat = "APL/%s/%d"
)

type (
	Transaction struct {
		ID            string      `json:"id"`
		SessionID     string      `json:"session_id"`
		ReferenceNo   string      `json:"reference_no"`
		Subtotal      int64       `json:"subtotal"`
		Discount      int64       `json:"discount"`
		TaxRate       float64     `json:"tax_rate"`
		Tax           int64       `json:"tax"`
		Total         int64       `json:"total"`
		PaymentMethod uint8       `json:"payment_method"`
		LineItems     []*LineItem `json:"line_items"`
		CreatedBy     string      `json:"created_by"`
		CreatedAt     time.Time   `json:"created_at"`
	}

	LineItem struct {
		ID            string `json:"id"`
		TransactionID string `json:"-"`
		ProductID     string `json:"product_id"`
		ProductName   string `json:"product_name"`
		ProductUOM    string `json:"product_uom"`
		Quantity      int64  `json:"quantity"`
		Price         int64  `json:"price"`
		Subtotal      int64  `json:"subtotal"`
	}

	Filter struct {
		TransactionIDs,
		SessionIDs,
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
	ErrUniqueReferenceNoViolation = errors.New("reference_no: already exists")
)

func (q *Transaction) Validate() error {
	if len(q.LineItems) == 0 {
		return errors.New("line_items: cannot be empty")
	}
	mapProductIDs := map[string]int{}
	for i, lineItem := range q.LineItems {
		if lineItem.ProductID = strings.TrimSpace(lineItem.ProductID); lineItem.ProductID == "" {
			return fmt.Errorf("line_items[%d].product_id: is required", i)
		}
		if _, ok := mapProductIDs[lineItem.ProductID]; ok {
			return fmt.Errorf("line_items[%d].product_id: cannot be reused for different line items", i)
		}
		mapProductIDs[lineItem.ProductID] = i
		if lineItem.Quantity == 0 {
			return fmt.Errorf("line_items[%d].quantity: cannot be empty", i)
		}
	}
	if q.PaymentMethod != PaymentMethodCash &&
		q.PaymentMethod != PaymentMethodBankTransfer {
		return fmt.Errorf("payment_method: should be either %d (cash) / %d (bank transfer)", PaymentMethodCash, PaymentMethodBankTransfer)
	}
	return nil
}

func (q *Transaction) Calculate(products map[string]*productModel.Product) error {
	q.Subtotal = 0
	for i, lineItem := range q.LineItems {
		product, ok := products[lineItem.ProductID]
		if !ok {
			return fmt.Errorf("line_items[%d]:product_id %s not found", i, lineItem.ProductID)
		}
		if product.Stock == 0 {
			return fmt.Errorf("line_items[%d]:product_id %s is out of stock", i, lineItem.ProductID)
		}
		lineItem.ProductName = product.Name
		lineItem.ProductUOM = product.UOM
		lineItem.Price = product.Price
		if lineItem.Quantity > product.Stock {
			return fmt.Errorf("line_items[%d]:quantity %d exceeds stock", i, lineItem.Quantity)
		}
		lineItem.Subtotal = lineItem.Price * lineItem.Quantity
		q.Subtotal += lineItem.Subtotal
		q.LineItems[i] = lineItem
	}
	subtotal := q.Subtotal
	if q.Discount > q.Subtotal {
		return errors.New("discount cannot exceed subtotal")
	}
	subtotal -= q.Discount
	q.TaxRate = helper.GetTaxRate()
	subtotalDecimal, err := decimal.New(subtotal, 0)
	if err != nil {
		return err
	}
	taxRateDecimal, err := decimal.NewFromFloat64(q.TaxRate)
	if err != nil {
		return err
	}
	hundredDecimal, err := decimal.New(100, 0)
	if err != nil {
		return err
	}
	taxDecimal, err := subtotalDecimal.Mul(taxRateDecimal)
	if err != nil {
		return err
	}
	if taxDecimal, err = taxDecimal.Quo(hundredDecimal); err != nil {
		return err
	}
	q.Tax, _, _ = taxDecimal.Int64(0)
	q.Total = subtotal + q.Tax
	return nil
}

func NewFilter(options ...FilterOption) *Filter {
	filter := &Filter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func WithTransactionIDs(transactioIDs ...string) FilterOption {
	return func(q *Filter) {
		q.TransactionIDs = transactioIDs
	}
}

func WithSessionIDs(sessionIDs ...string) FilterOption {
	return func(q *Filter) {
		q.SessionIDs = sessionIDs
	}
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
