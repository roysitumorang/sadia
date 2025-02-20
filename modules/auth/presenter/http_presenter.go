package presenter

import (
	"crypto/rsa"
	"errors"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/middleware"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	authModel "github.com/roysitumorang/sadia/modules/auth/model"
	"github.com/roysitumorang/sadia/modules/auth/sanitizer"
	jwtModel "github.com/roysitumorang/sadia/modules/jwt/model"
	jwtUseCase "github.com/roysitumorang/sadia/modules/jwt/usecase"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type (
	authHTTPHandler struct {
		jwtUseCase     jwtUseCase.JwtUseCase
		accountUseCase accountUseCase.AccountUseCase
		privateKey     *rsa.PrivateKey
		accessTokenAge time.Duration
	}
)

func New(
	jwtUseCase jwtUseCase.JwtUseCase,
	accountUseCase accountUseCase.AccountUseCase,
	privateKey *rsa.PrivateKey,
	accessTokenAge time.Duration,
) *authHTTPHandler {
	return &authHTTPHandler{
		jwtUseCase:     jwtUseCase,
		accountUseCase: accountUseCase,
		privateKey:     privateKey,
		accessTokenAge: accessTokenAge,
	}
}

func (q *authHTTPHandler) Mount(r fiber.Router) {
	r.Post("/login", q.Login)
	r.Get("/me", middleware.KeyAuth(q.jwtUseCase, q.accountUseCase), q.Me)
}

func (q *authHTTPHandler) Login(c *fiber.Ctx) error {
	ctx := c.UserContext()
	ctxt := "AuthPresenter-Login"
	request, statusCode, err := sanitizer.Login(ctx, c)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrLogin")
		return helper.NewResponse(statusCode).SetMessage(err.Error()).WriteResponse(c)
	}
	accounts, _, err := q.accountUseCase.FindAccounts(
		ctx,
		accountModel.NewFilter(accountModel.WithLogin(request.Login)),
		url.Values{},
	)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrLogin")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if len(accounts) == 0 ||
		accounts[0].Status != accountModel.StatusActive ||
		accounts[0].EncryptedPassword == nil {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	account := accounts[0]
	encryptedPassword := helper.String2ByteSlice(*account.EncryptedPassword)
	password, err := request.DecodePassword()
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrDecodePassword")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	err = bcrypt.CompareHashAndPassword(encryptedPassword, password)
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	jwtID, jwtUID, jwtToken, err := helper.GenerateUniqueID()
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateUniqueID")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	now := time.Now()
	jwt := jwtModel.JsonWebToken{
		ID:         jwtID,
		UID:        jwtUID,
		Token:      jwtToken,
		AccountUID: account.UID,
		CreatedAt:  now,
		ExpiredAt:  now.Add(q.accessTokenAge),
	}
	tokenString, err := helper.GenerateAccessToken(account.UID, jwtToken, account.Username, jwt.CreatedAt, jwt.ExpiredAt, q.privateKey)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrGenerateAccessToken")
		return helper.NewResponse(fiber.StatusBadRequest).SetMessage("login failed").WriteResponse(c)
	}
	ipAddress := c.IP()
	account.LoginCount++
	account.LastLoginAt = account.CurrentLoginAt
	account.LastLoginIP = account.CurrentLoginIP
	account.CurrentLoginAt = &now
	account.CurrentLoginIP = &ipAddress
	tx, err := q.accountUseCase.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	defer func() {
		errRollback := tx.Rollback(ctx)
		if errors.Is(errRollback, pgx.ErrTxClosed) {
			errRollback = nil
		}
		if errRollback != nil {
			helper.Log(ctx, zap.ErrorLevel, errRollback.Error(), ctxt, "ErrRollback")
		}
	}()
	if err = q.jwtUseCase.CreateJWT(ctx, tx, jwt); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateJWT")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = q.accountUseCase.UpdateAccount(ctx, tx, account); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	if err = tx.Commit(ctx); err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCommit")
		return helper.NewResponse(fiber.StatusUnprocessableEntity).SetMessage(err.Error()).WriteResponse(c)
	}
	response := authModel.LoginResponse{
		IDToken:   tokenString,
		ExpiredAt: jwt.ExpiredAt,
		Account:   account,
	}
	return helper.NewResponse(fiber.StatusCreated).SetData(response).WriteResponse(c)
}

func (q *authHTTPHandler) Me(c *fiber.Ctx) error {
	response := c.Locals(models.CurrentAccount)
	return helper.NewResponse(fiber.StatusOK).SetData(response).WriteResponse(c)
}
