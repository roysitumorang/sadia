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
	"github.com/roysitumorang/sadia/services"
)

func AdminKeyAuth(
	jwtService services.JwtService,
	accountService services.AccountService,
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
			jsonWebTokens, _, err := jwtService.FindJWTs(
				ctx,
				models.NewJwtFilter(
					models.JwtWithTokens(claims.Subject),
				),
			)
			if err != nil || len(jsonWebTokens) == 0 {
				return false, err
			}
			jwt := jsonWebTokens[0]
			admins, _, err := accountService.FindAdmins(
				ctx,
				models.NewAccountFilter(
					models.AccountWithAccountIDs(jwt.AccountID),
					models.AccountWithAdminLevels(adminLevels...),
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
	jwtService services.JwtService,
	accountService services.AccountService,
	companyService services.CompanyService,
	sessionService services.SessionService,
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
			jsonWebTokens, _, err := jwtService.FindJWTs(
				ctx,
				models.NewJwtFilter(
					models.JwtWithTokens(claims.Subject),
				),
			)
			if err != nil || len(jsonWebTokens) == 0 {
				return false, err
			}
			jwt := jsonWebTokens[0]
			users, _, err := accountService.FindUsers(
				ctx,
				models.NewAccountFilter(
					models.AccountWithAccountIDs(jwt.AccountID),
					models.AccountWithUserLevels(userLevels...),
				),
			)
			if err != nil || len(users) == 0 {
				return false, err
			}
			currentUser := users[0]
			companies, _, err := companyService.FindCompanies(
				ctx,
				models.NewCompanyFilter(
					models.CompanyWithCompanyIDs(currentUser.CompanyID),
				),
			)
			if err != nil || len(companies) == 0 {
				return false, err
			}
			currentCompany := companies[0]
			if currentCompany.SessionID != nil {
				sessions, _, err := sessionService.FindSessions(
					ctx,
					models.NewSessionFilter(
						models.SessionWithSessionIDs(*currentCompany.SessionID),
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
