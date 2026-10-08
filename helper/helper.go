package helper

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unsafe"
	"uuid"

	"github.com/goccy/go-json"
	"github.com/godruoyi/go-snowflake"
	"github.com/golang-jwt/jwt/v5"
	"github.com/roysitumorang/sadia/keys"
	"github.com/roysitumorang/sadia/pools"
	"github.com/sqids/sqids-go"
	"golang.org/x/crypto/bcrypt"
)

const numbers = "0123456789"
const base58alphabets = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const lowerCasedAlphabets = "123456789abcdefghijkmnopqrstuvwxyz"

var timeZone *time.Location
var env string
var jwtIssuer string
var kafkaBrokers []string
var loginMaxFailedAttempts int
var loginLockoutDuration time.Duration
var accessTokenAge time.Duration
var sqIDs *sqids.Sqids
var privateKey *rsa.PrivateKey
var InitHelper = sync.OnceValue(func() (err error) {
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
	envKafkaBrokers, ok := os.LookupEnv("KAFKA_BROKERS")
	if !ok || envKafkaBrokers == "" {
		return errors.New("env KAFKA_BROKERS is required")
	}
	kafkaBrokers = strings.Split(envKafkaBrokers, ";")
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
	envAccesTokenAge, ok := os.LookupEnv("ACCESS_TOKEN_AGE")
	if !ok || envAccesTokenAge == "" {
		return errors.New("env ACCESS_TOKEN_AGE is required")
	}
	if accessTokenAge, err = time.ParseDuration(envAccesTokenAge); err != nil {
		return
	}
	privateKey, err = keys.InitPrivateKey()
	return
})

func String2ByteSlice(str string) []byte {
	return unsafe.Slice(unsafe.StringData(str), len(str))
}

func ByteSlice2String(bs []byte) string {
	return *(*string)(unsafe.Pointer(&bs))
}

func GenerateSnowflakeID() uint64 {
	return snowflake.ID()
}

func EncodeSqids(numbers ...uint64) (string, error) {
	if len(numbers) == 0 {
		return "", nil
	}
	return sqIDs.Encode(numbers)
}

func DecodeSqids(id string) uint64 {
	if id == "" {
		return 0
	}
	numbers := sqIDs.Decode(id)
	if len(numbers) == 0 {
		return 0
	}
	return numbers[0]
}

func GenerateUniqueID() string {
	return uuid.NewV4().String()
}

func LoadTimeZone() *time.Location {
	return timeZone
}

func GetEnv() string {
	return env
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

func GenerateAccessToken(id, subject, audience string, createdAt, expiredAt time.Time) (string, error) {
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

func GetKafkaBrokers() []string {
	return kafkaBrokers
}

// RandomString generate random string
func RandomString(length int) string {
	randomBytes := make([]byte, length)
	for {
		if _, err := rand.Read(randomBytes); err == nil {
			break
		}
	}
	for i := range length {
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
	for i := range length {
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
	hashByte, err := bcrypt.GenerateFromPassword(String2ByteSlice(password), bcrypt.DefaultCost)
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

func GetAccessTokenAge() time.Duration {
	return accessTokenAge
}

func Sprintf(format string, a ...any) string {
	sb := pools.BuilderPool.Get()
	defer func() {
		sb.Reset()
		pools.BuilderPool.Put(sb)
	}()
	_, _ = fmt.Fprintf(sb, format, a...)
	return sb.String()
}
