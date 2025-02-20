package middleware

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/keyauth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/keys"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
)

func KeyAuth(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	accountTypes ...uint8,
) func(c *fiber.Ctx) error {
	var builder strings.Builder
	_, _ = builder.WriteString("header:")
	_, _ = builder.WriteString(fiber.HeaderAuthorization)
	return keyauth.New(keyauth.Config{
		SuccessHandler: func(c *fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == nil {
				err = keyauth.ErrMissingOrMalformedAPIKey
			}
			return helper.NewResponse(fiber.StatusUnauthorized).SetMessage(err.Error()).WriteResponse(c)
		},
		KeyLookup:  builder.String(),
		AuthScheme: "Bearer",
		Validator: func(c *fiber.Ctx, token string) (bool, error) {
			claims, err := bearerVerify(token)
			if err != nil {
				return false, err
			}
			ctx := c.UserContext()
			jsonWebTokens, _, err := jwtUseCase.FindJWTs(ctx, jwtModel.NewFilter(jwtModel.WithTokens(claims.Subject)), url.Values{})
			if err != nil || len(jsonWebTokens) == 0 {
				return false, err
			}
			jwt := jsonWebTokens[0]
			accounts, _, err := accountUseCase.FindAccounts(ctx, accountModel.NewFilter(accountModel.WithAccountUIDs(jwt.AccountUID)), url.Values{})
			if err != nil || len(accounts) == 0 {
				return false, err
			}
			account := accounts[0]
			if len(accountTypes) > 0 {
				var matched bool
				for _, _accountType := range accountTypes {
					if matched = account.AccountType == _accountType; matched {
						break
					}
				}
				if !matched {
					return false, nil
				}
			}
			c.Locals(models.CurrentAccount, &account)
			return true, nil
		},
		ContextKey: "token",
	})
}

func bearerVerify(tokenString string) (*jwt.RegisteredClaims, error) {
	var claimsStruct jwt.RegisteredClaims
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claimsStruct,
		func(_ *jwt.Token) (interface{}, error) {
			return keys.InitPublicKey()
		},
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid JWT")
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, errors.New("invalid JWT")
	}
	if claims.Issuer != helper.GetJwtIssuer() {
		return nil, errors.New("iss is invalid")
	}
	if claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("JWT is expired")
	}
	return claims, nil
}
