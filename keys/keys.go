package keys

import (
	"crypto/rsa"
	"encoding/base64"
	"os"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

var (
	InitPublicKey = sync.OnceValues[*rsa.PublicKey, error](func() (*rsa.PublicKey, error) {
		verifyBytes, err := base64.StdEncoding.DecodeString(os.Getenv("RSA_PUBLIC_KEY"))
		if err != nil {
			return nil, err
		}
		return jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	})

	InitPrivateKey = sync.OnceValues[*rsa.PrivateKey, error](func() (*rsa.PrivateKey, error) {
		signBytes, err := base64.StdEncoding.DecodeString(os.Getenv("RSA_PRIVATE_KEY"))
		if err != nil {
			return nil, err
		}
		return jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	})
)
