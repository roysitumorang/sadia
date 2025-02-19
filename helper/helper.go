package helper

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"maps"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/roysitumorang/sadia/models"
	"github.com/vishal-bihani/go-tsid"
)

var (
	timeZone *time.Location
	env,
	jwtIssuer string
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
		if jwtIssuer, ok = os.LookupEnv("JWT_ISSUER"); !ok || jwtIssuer == "" {
			err = errors.New("env JWT_ISSUER is required")
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

func SetPagination(total, pages, limit, page int64, baseURL string, urlValues url.Values) (*models.Pagination, error) {
	var response models.Pagination
	response.Info.Total = total
	response.Info.Pages = pages
	response.Info.Limit = limit
	response.Links.First = baseURL
	response.Links.Current = baseURL
	var builder strings.Builder
	if len(urlValues) > 0 {
		queryString, err := url.QueryUnescape(urlValues.Encode())
		if err != nil {
			return nil, err
		}
		builder.Reset()
		_, _ = builder.WriteString(baseURL)
		_, _ = builder.WriteString("?")
		_, _ = builder.WriteString(queryString)
		url := builder.String()
		response.Links.First = url
		response.Links.Current = url
	}
	if page < pages {
		u := maps.Clone(urlValues)
		u.Set("page", strconv.FormatInt(page+1, 10))
		queryString, err := url.QueryUnescape(u.Encode())
		if err != nil {
			return nil, err
		}
		builder.Reset()
		_, _ = builder.WriteString(baseURL)
		_, _ = builder.WriteString("?")
		_, _ = builder.WriteString(queryString)
		response.Links.Next = builder.String()
	}
	if page > 1 {
		u := maps.Clone(urlValues)
		queryString, err := url.QueryUnescape(u.Encode())
		if err != nil {
			return nil, err
		}
		builder.Reset()
		_, _ = builder.WriteString(baseURL)
		_, _ = builder.WriteString("?")
		_, _ = builder.WriteString(queryString)
		response.Links.Previous = builder.String()
		u.Set("page", strconv.FormatInt(page, 10))
		if queryString, err = url.QueryUnescape(u.Encode()); err != nil {
			return nil, err
		}
		builder.Reset()
		_, _ = builder.WriteString(baseURL)
		_, _ = builder.WriteString("?")
		_, _ = builder.WriteString(queryString)
		response.Links.Current = builder.String()
		if page > 2 {
			u.Set("page", strconv.FormatInt(page-1, 10))
			if queryString, err = url.QueryUnescape(u.Encode()); err != nil {
				return nil, err
			}
			builder.Reset()
			_, _ = builder.WriteString(baseURL)
			_, _ = builder.WriteString("?")
			_, _ = builder.WriteString(queryString)
			response.Links.Previous = builder.String()
		}
	}
	return &response, nil
}

func Transcode(input, output interface{}) error {
	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(input); err != nil {
		return err
	}
	return json.NewDecoder(buffer).Decode(output)
}

func GetJwtIssuer() string {
	return jwtIssuer
}

func GenerateAccessToken(id, subject, audience string, createdAt, expiredAt time.Time, privateKey *rsa.PrivateKey) (string, error) {
	numericDate := jwt.NewNumericDate(createdAt)
	var claims jwt.RegisteredClaims
	claims.ID = id
	claims.Subject = subject
	claims.Audience = append(claims.Audience, audience)
	claims.Issuer = jwtIssuer
	claims.IssuedAt = numericDate
	claims.NotBefore = numericDate
	claims.ExpiresAt = jwt.NewNumericDate(expiredAt)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}
