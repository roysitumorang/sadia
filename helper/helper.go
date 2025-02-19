package helper

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/roysitumorang/sadia/models"
	"github.com/vishal-bihani/go-tsid"
)

var (
	timeZone   *time.Location
	env        string
	InitHelper = sync.OnceValue(func() (err error) {
		location, ok := os.LookupEnv("TIME_ZONE")
		if !ok || location == "" {
			return errors.New("env TIME_ZONE is required")
		}
		if timeZone, err = time.LoadLocation(location); err != nil {
			return
		}
		if env, ok = os.LookupEnv("ENV"); !ok {
			return errors.New("env ENV is required")
		}
		if env == "" {
			env = "development"
		}
		return
	})
)

func String2ByteSlice(str string) []byte {
	return unsafe.Slice(unsafe.StringData(str), len(str))
}

func ByteSlice2String(bs []byte) string {
	return *(*string)(unsafe.Pointer(&bs))
}

func GenerateSnowflakeID() int64 {
	return tsid.Fast().ToNumber()
}

func GenerateUniqueID() (uniqueID int64, sqID string, uuID string, err error) {
	uuidV7, err := uuid.NewV7()
	if err != nil {
		return
	}
	tsid := tsid.Fast()
	return tsid.ToNumber(), tsid.ToLowerCase(), uuidV7.String(), nil
}

func LoadTimeZone() *time.Location {
	return timeZone
}

func GetEnv() string {
	return env
}

func SetPagination(total, pages, limit, page uint64, baseURL string, urlValues url.Values) (response models.Pagination, err error) {
	response.Info.Total = total
	response.Info.Pages = pages
	response.Info.Limit = limit
	response.Links.First = baseURL
	response.Links.Current = baseURL
	if len(urlValues) > 0 {
		queryString, err := url.QueryUnescape(urlValues.Encode())
		if err != nil {
			return response, err
		}
		url := fmt.Sprintf("%s?%s", baseURL, queryString)
		response.Links.First = url
		response.Links.Current = url
	}
	if page < pages {
		u := maps.Clone(urlValues)
		u.Set("page", strconv.FormatUint(page+1, 10))
		queryString, err := url.QueryUnescape(u.Encode())
		if err != nil {
			return response, err
		}
		response.Links.Next = fmt.Sprintf("%s?%s", baseURL, queryString)
	}
	if page > 1 {
		u := maps.Clone(urlValues)
		queryString, err := url.QueryUnescape(u.Encode())
		if err != nil {
			return response, err
		}
		response.Links.Previous = fmt.Sprintf("%s?%s", baseURL, queryString)
		u.Set("page", strconv.FormatUint(page, 10))
		if queryString, err = url.QueryUnescape(u.Encode()); err != nil {
			return response, err
		}
		response.Links.Current = fmt.Sprintf("%s?%s", baseURL, queryString)
		if page > 2 {
			u.Set("page", strconv.FormatUint(page-1, 10))
			if queryString, err = url.QueryUnescape(u.Encode()); err != nil {
				return response, err
			}
			response.Links.Previous = fmt.Sprintf("%s?%s", baseURL, queryString)
		}
	}
	return
}

func Transcode(input, output interface{}) error {
	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(input); err != nil {
		return err
	}
	return json.NewDecoder(buffer).Decode(output)
}
