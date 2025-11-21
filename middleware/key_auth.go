package middleware

import (
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/keyauth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/keys"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
	sessionUseCase "github.com/roysitumorang/sadia/modules/session/usecase"
)

func AdminKeyAuth(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	adminLevels ...uint8,
) fiber.Handler {
	var builder strings.Builder
	_, _ = builder.WriteString("header:")
	_, _ = builder.WriteString(fiber.HeaderAuthorization)
	return keyauth.New(keyauth.Config{
		SuccessHandler: func(c fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c fiber.Ctx, err error) error {
			if err == nil {
				err = keyauth.ErrMissingOrMalformedAPIKey
			}
			return helper.NewResponse(fiber.StatusUnauthorized).SetMessage(err.Error()).WriteResponse(c)
		},
		Validator: func(c fiber.Ctx, token string) (bool, error) {
			claims, err := bearerVerify(token)
			if err != nil {
				return false, err
			}
			ctx := c.Context()
			jsonWebTokens, _, err := jwtUseCase.FindJWTs(
				ctx,
				jwtModel.NewFilter(
					jwtModel.WithTokens(claims.Subject),
				),
			)
			if err != nil || len(jsonWebTokens) == 0 {
				return false, err
			}
			jwt := jsonWebTokens[0]
			admins, _, err := accountUseCase.FindAdmins(
				ctx,
				accountModel.NewFilter(
					accountModel.WithAccountIDs(jwt.AccountID),
					accountModel.WithAdminLevels(adminLevels...),
				),
			)
			if err != nil || len(admins) == 0 {
				return false, err
			}
			admin := admins[0]
			c.Locals(models.CurrentAdmin, admin)
			c.Locals(models.CurrentJwt, claims)
			return true, nil
		},
	})
}

func UserKeyAuth(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
	userLevels ...uint8,
) fiber.Handler {
	var builder strings.Builder
	_, _ = builder.WriteString("header:")
	_, _ = builder.WriteString(fiber.HeaderAuthorization)
	return keyauth.New(keyauth.Config{
		SuccessHandler: func(c fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c fiber.Ctx, err error) error {
			if err == nil {
				err = keyauth.ErrMissingOrMalformedAPIKey
			}
			return helper.NewResponse(fiber.StatusUnauthorized).SetMessage(err.Error()).WriteResponse(c)
		},
		Validator: func(c fiber.Ctx, token string) (bool, error) {
			claims, err := bearerVerify(token)
			if err != nil {
				return false, err
			}
			ctx := c.Context()
			jsonWebTokens, _, err := jwtUseCase.FindJWTs(
				ctx,
				jwtModel.NewFilter(
					jwtModel.WithTokens(claims.Subject),
				),
			)
			if err != nil || len(jsonWebTokens) == 0 {
				return false, err
			}
			jwt := jsonWebTokens[0]
			users, _, err := accountUseCase.FindUsers(
				ctx,
				accountModel.NewFilter(
					accountModel.WithAccountIDs(jwt.AccountID),
					accountModel.WithUserLevels(userLevels...),
				),
			)
			if err != nil || len(users) == 0 {
				return false, err
			}
			currentUser := users[0]
			companies, _, err := companyUseCase.FindCompanies(
				ctx,
				companyModel.NewFilter(
					companyModel.WithCompanyIDs(currentUser.CompanyID),
				),
			)
			if err != nil || len(companies) == 0 {
				return false, err
			}
			currentCompany := companies[0]
			if currentCompany.SessionID != nil {
				sessions, _, err := sessionUseCase.FindSessions(
					ctx,
					sessionModel.NewFilter(
						sessionModel.WithSessionIDs(*currentCompany.SessionID),
					),
				)
				if err != nil || len(sessions) == 0 {
					return false, err
				}
				c.Locals(models.CurrentSession, sessions[0])
			}
			c.Locals(models.CurrentJwt, claims)
			c.Locals(models.CurrentUser, currentUser)
			c.Locals(models.CurrentCompany, currentCompany)
			return true, nil
		},
	})
}

func bearerVerify(tokenString string) (*jwt.RegisteredClaims, error) {
	var claimsStruct jwt.RegisteredClaims
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claimsStruct,
		func(_ *jwt.Token) (any, error) {
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
