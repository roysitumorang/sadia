package model

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

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
		RowNo         uint64      `json:"row_no,omitempty"`
		ID            string      `json:"id"`
		SessionID     string      `json:"session_id"`
		ReferenceNo   string      `json:"reference_no"`
		Subtotal      int64       `json:"subtotal"`
		Discount      int64       `json:"discount"`
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
		ProductCode   string `json:"product_code"`
		ProductUOM    string `json:"product_uom"`
		BasePrice     int64  `json:"base_price"`
		SellingPrice  int64  `json:"selling_price"`
		Weight        int64  `json:"weight"`
		Quantity      int64  `json:"quantity"`
		Subtotal      int64  `json:"subtotal"`
	}

	Filter struct {
		TransactionIDs,
		SessionIDs,
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
			return fmt.Errorf("line_items[%d].product_id %s not found", i, lineItem.ProductID)
		}
		if product.Stock == 0 {
			return fmt.Errorf("line_items[%d].product_id %s is out of stock", i, lineItem.ProductID)
		}
		lineItem.ProductName = product.Name
		lineItem.ProductCode = product.Code
		lineItem.ProductUOM = product.UOM
		lineItem.BasePrice = product.BasePrice
		lineItem.SellingPrice = product.SellingPrice
		lineItem.Weight = product.Weight
		if lineItem.Quantity > product.Stock {
			return fmt.Errorf("line_items[%d]:quantity %d exceeds stock", i, lineItem.Quantity)
		}
		lineItem.Subtotal = lineItem.SellingPrice * lineItem.Quantity
		q.Subtotal += lineItem.Subtotal
		q.LineItems[i] = lineItem
	}
	if q.Discount > q.Subtotal {
		return errors.New("discount cannot exceed subtotal")
	}
	q.Total = q.Subtotal - q.Discount
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
