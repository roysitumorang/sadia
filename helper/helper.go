package helper

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"maps"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unsafe"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/roysitumorang/sadia/models"
	"github.com/vishal-bihani/go-tsid"
	"golang.org/x/crypto/bcrypt"
)

const (
	numbers         = "0123456789"
	base58alphabets = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var (
	timeZone *time.Location
	env,
	jwtIssuer,
	nsqAddress string
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
			return errors.New("env JWT_ISSUER is required")
		}
		if nsqAddress, ok = os.LookupEnv("NSQ_ADDRESS"); !ok || nsqAddress == "" {
			err = errors.New("env NSQ_ADDRESS is required")
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

func GetNsqAddress() string {
	return nsqAddress
}

// RandomString generate random string
func RandomString(length int) string {
	randomBytes := make([]byte, length)
	for {
		if _, err := rand.Read(randomBytes); err == nil {
			break
		}
	}
	for i := 0; i < length; i++ {
		randomBytes[i] = base58alphabets[randomBytes[i]%58]
	}
	return ByteSlice2String(randomBytes)
}

// RandomNumber generate random number
func RandomNumber(length int) string {
	randomBytes := make([]byte, length)
	for {
		if _, err := rand.Read(randomBytes); err == nil {
			break
		}
	}
	for i := 0; i < length; i++ {
		randomBytes[i] = numbers[randomBytes[i]%10]
	}
	return ByteSlice2String(randomBytes)
}

func ValidPassword(password string) bool {
	var hasUpperCase,
		hasLowerCase,
		hasNumber,
		hasSymbol bool
	length := len(password)
	for _, char := range password {
		hasUpperCase = hasUpperCase || unicode.IsUpper(char)
		hasLowerCase = hasLowerCase || unicode.IsLower(char)
		hasNumber = hasNumber || unicode.IsNumber(char)
		hasSymbol = hasSymbol || unicode.IsPunct(char) || unicode.IsSymbol(char)
	}
	return hasUpperCase &&
		hasLowerCase &&
		hasNumber &&
		hasSymbol &&
		length >= 8
}

func HashPassword(password string) (*string, error) {
	hashByte, err := bcrypt.GenerateFromPassword(String2ByteSlice(password), bcrypt.MinCost)
	if err != nil {
		return nil, err
	}
	hashString := ByteSlice2String(hashByte)
	return &hashString, nil
}

func MatchedHashAndPassword(encryptedPassword, password []byte) bool {
	err := bcrypt.CompareHashAndPassword(encryptedPassword, password)
	return !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword)
}

func Base64Decode(input string) (string, error) {
	output, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		if _, ok := err.(base64.CorruptInputError); ok {
			err = errors.New("malformed input")
		}
		return "", err
	}
	return ByteSlice2String(output), nil
}
