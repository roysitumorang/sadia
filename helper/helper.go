package helper

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"math"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/roysitumorang/sadia/models"
	"github.com/sqids/sqids-go"
	"github.com/vishal-bihani/go-tsid"
	"golang.org/x/crypto/bcrypt"
)

const (
	numbers             = "0123456789"
	base58alphabets     = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	lowerCasedAlphabets = "123456789abcdefghijkmnopqrstuvwxyz"
)

var (
	timeZone *time.Location
	env,
	jwtIssuer,
	nsqAddress string
	loginMaxFailedAttempts int
	loginLockoutDuration   time.Duration
	sqIDs                  *sqids.Sqids
	dbWrite                *pgxpool.Pool
	taxRate                float64
	InitHelper             = sync.OnceValue(func() (err error) {
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
			return errors.New("env NSQ_ADDRESS is required")
		}
		envLoginMaxFailedAttempts, ok := os.LookupEnv("LOGIN_MAX_FAILED_ATTEMPTS")
		if !ok || envLoginMaxFailedAttempts == "" {
			return errors.New("env LOGIN_MAX_FAILED_ATTEMPTS is required")
		}
		if loginMaxFailedAttempts, err = strconv.Atoi(envLoginMaxFailedAttempts); err != nil || loginMaxFailedAttempts < 1 {
			return errors.New("env LOGIN_MAX_FAILED_ATTEMPS requires a positive integer")
		}
		envLoginLockoutDuration, ok := os.LookupEnv("LOGIN_LOCKOUT_DURATION")
		if !ok || envLoginLockoutDuration == "" {
			return errors.New("env LOGIN_LOCKOUT_DURATION is required")
		}
		if loginLockoutDuration, err = time.ParseDuration(envLoginLockoutDuration); err != nil {
			return
		}
		envSqidsMinLength, ok := os.LookupEnv("SQIDS_MIN_LENGTH")
		if !ok || envSqidsMinLength == "" {
			return errors.New("env SQIDS_MIN_LENGTH is required")
		}
		sqidsMinLength, err := strconv.Atoi(envSqidsMinLength)
		if err != nil || sqidsMinLength < 1 || sqidsMinLength > math.MaxUint8 {
			return fmt.Errorf("env SQIDS_MIN_LENGTH requires a positive integer, min. 1, max %d", math.MaxUint8)
		}
		if sqIDs, err = sqids.New(sqids.Options{
			Alphabet:  lowerCasedAlphabets,
			MinLength: uint8(sqidsMinLength),
		}); err != nil {
			return
		}
		envTaxRate, ok := os.LookupEnv("TAX_RATE")
		if !ok || envTaxRate == "" {
			return errors.New("env TAX_RATE is required")
		}
		if taxRate, err = strconv.ParseFloat(envTaxRate, 64); err != nil || taxRate < 1 {
			err = errors.New("env TAX_RATE requires a positive integer")
		}
		return
	})
)

func InitDbWrite(dbWriteOnly *pgxpool.Pool) {
	dbWrite = dbWriteOnly
}

func BeginTx(ctx context.Context) (pgx.Tx, error) {
	return dbWrite.Begin(ctx)
}

func String2ByteSlice(str string) []byte {
	return unsafe.Slice(unsafe.StringData(str), len(str))
}

func ByteSlice2String(bs []byte) string {
	return *(*string)(unsafe.Pointer(&bs))
}

func GenerateSnowflakeID() int64 {
	return tsid.Fast().ToNumber()
}

func EncodeSqids(numbers ...int64) (string, error) {
	n := len(numbers)
	if n == 0 {
		return "", nil
	}
	unsignedNumbers := make([]uint64, len(numbers))
	for i, number := range numbers {
		unsignedNumbers[i] = uint64(number)
	}
	return sqIDs.Encode(unsignedNumbers)
}

func DecodeSqids(id string) int64 {
	if id == "" {
		return 0
	}
	unsignedNumbers := sqIDs.Decode(id)
	if len(unsignedNumbers) == 0 {
		return 0
	}
	return int64(unsignedNumbers[0])
}

func GenerateUniqueID() (uniqueID int64, sqID string, uuID string, err error) {
	uuidV4, err := uuid.NewRandom()
	if err != nil {
		return
	}
	uniqueID = GenerateSnowflakeID()
	if sqID, err = EncodeSqids(uniqueID); err != nil {
		return
	}
	uuID = uuidV4.String()
	return
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

func Transcode(input, output any) error {
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

func GetLoginMaxFailedAttempts() int {
	return loginMaxFailedAttempts
}

func GetLoginLockoutDuration() time.Duration {
	return loginLockoutDuration
}

func GetTaxRate() float64 {
	return taxRate
}
