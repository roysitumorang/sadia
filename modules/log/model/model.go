package model

import (
	"net/url"
	"time"
)

const (
	ActionCreate     = "create"
	ActionUpdate     = "update"
	ActionDeactivate = "deactivate"
)

type (
	Log struct {
		RowNo     uint64            `json:"row_no,omitempty" form:"-"`
		ID        uint64            `json:"id,string" form:"-"`
		CompanyID uint64            `json:"-" form:"-"`
		TableName string            `json:"-" form:"-"`
		TableID   uint64            `json:"-" form:"-"`
		Action    string            `json:"activity" form:"-"`
		Changes   map[string]Change `json:"changes" form:"-"`
		CreatedBy uint64            `json:"-" form:"-"`
		CreatedAt time.Time         `json:"-" form:"-"`
	}

	Change struct {
		Old any `json:"old,omitempty" form:"-"`
		New any `json:"new" form:"-"`
	}

	Filter struct {
		LogIDs,
		CompanyIDs,
		TableIDs []uint64
		TableNames    []string
		PaginationURL string
		Limit,
		Page int64
		UrlValues url.Values
	}

	FilterOption func(q *Filter)
)

func NewFilter(options ...FilterOption) *Filter {
	filter := &Filter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func WithLogIDs(logIDs ...uint64) FilterOption {
	return func(q *Filter) {
		q.LogIDs = logIDs
	}
}

func WithCompanyIDs(companyIDs ...uint64) FilterOption {
	return func(q *Filter) {
		q.CompanyIDs = companyIDs
	}
}

func WithTableIDs(tableIDs ...uint64) FilterOption {
	return func(q *Filter) {
		q.TableIDs = tableIDs
	}
}

func WithTableNames(tableNames ...string) FilterOption {
	return func(q *Filter) {
		q.TableNames = tableNames
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
