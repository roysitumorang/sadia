package models

import (
	"net/url"
	"time"
)

const ActionCreate = "create"
const ActionUpdate = "update"
const ActionDeactivate = "deactivate"

type Log struct {
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

type Change struct {
	Old any `json:"old,omitempty" form:"-"`
	New any `json:"new" form:"-"`
}

type LogFilter struct {
	LogIDs,
	CompanyIDs,
	TableIDs []uint64
	TableNames    []string
	PaginationURL string
	Limit,
	Page int64
	UrlValues url.Values
}

type LogFilterOption func(q *LogFilter)

func NewLogFilter(options ...LogFilterOption) *LogFilter {
	filter := &LogFilter{UrlValues: url.Values{}}
	for _, option := range options {
		option(filter)
	}
	return filter
}

func LogWithLogIDs(logIDs ...uint64) LogFilterOption {
	return func(q *LogFilter) {
		q.LogIDs = logIDs
	}
}

func LogWithCompanyIDs(companyIDs ...uint64) LogFilterOption {
	return func(q *LogFilter) {
		q.CompanyIDs = companyIDs
	}
}

func LogWithTableIDs(tableIDs ...uint64) LogFilterOption {
	return func(q *LogFilter) {
		q.TableIDs = tableIDs
	}
}

func LogWithTableNames(tableNames ...string) LogFilterOption {
	return func(q *LogFilter) {
		q.TableNames = tableNames
	}
}

func LogWithPaginationURL(paginationURL string) LogFilterOption {
	return func(q *LogFilter) {
		q.PaginationURL = paginationURL
	}
}

func LogWithLimit(limit int64) LogFilterOption {
	return func(q *LogFilter) {
		q.Limit = limit
	}
}

func LogWithPage(page int64) LogFilterOption {
	return func(q *LogFilter) {
		q.Page = page
	}
}

func LogWithUrlValues(urlValues url.Values) LogFilterOption {
	return func(q *LogFilter) {
		q.UrlValues = urlValues
	}
}
