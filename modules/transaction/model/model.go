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
	CurrentCart       = "cart"
)

type (
	Transaction struct {
		RowNo         uint64      `json:"row_no,omitempty"`
		ID            string      `json:"id"`
		SessionID     string      `json:"session_id"`
		ReferenceNo   string      `json:"reference_no"`
		SubTotal      int64       `json:"subtotal"`
		Discount      int64       `json:"discount"`
		Total         int64       `json:"total"`
		PaymentMethod uint8       `json:"payment_method"`
		LineItems     []*LineItem `json:"line_items"`
		CreatedBy     string      `json:"created_by"`
		CreatedAt     time.Time   `json:"created_at"`
	}

	LineItem struct {
		ID            string `json:"id" form:"-"`
		TransactionID string `json:"-" form:"-"`
		ProductID     string `json:"product_id" form:"product_id"`
		ProductName   string `json:"product_name" form:"-"`
		ProductCode   string `json:"product_code" form:"-"`
		ProductUOM    string `json:"product_uom" form:"-"`
		Stock         int64  `json:"-" form:"-"`
		BasePrice     int64  `json:"base_price" form:"-"`
		SellingPrice  int64  `json:"selling_price" form:"-"`
		Weight        int64  `json:"weight" form:"-"`
		Quantity      int64  `json:"quantity" form:"quantity"`
		SubTotal      int64  `json:"subtotal" form:"-"`
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
			return fmt.Errorf("line_items[%d].product_id: cannot be reused for other line items", i)
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

func (q *LineItem) Validate() error {
	if q.ProductID = strings.TrimSpace(q.ProductID); q.ProductID == "" {
		return errors.New("product_id: is required")
	}
	if q.Quantity == 0 {
		return fmt.Errorf("quantity: is required, minimum 1")
	}
	return nil
}

func (q *Transaction) Calculate(products map[string]*productModel.Product) error {
	q.SubTotal = 0
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
		lineItem.Stock = product.Stock
		lineItem.BasePrice = product.BasePrice
		lineItem.SellingPrice = product.SellingPrice
		lineItem.Weight = product.Weight
		if lineItem.Quantity > product.Stock {
			return fmt.Errorf("line_items[%d]:quantity %d cannot exceed stock %d", i, lineItem.Quantity, product.Stock)
		}
		lineItem.SubTotal = lineItem.SellingPrice * lineItem.Quantity
		q.SubTotal += lineItem.SubTotal
		q.LineItems[i] = lineItem
	}
	if q.Discount > q.SubTotal {
		return errors.New("discount cannot exceed subtotal")
	}
	q.Total = q.SubTotal - q.Discount
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
