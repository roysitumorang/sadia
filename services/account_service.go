package services

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"go.uber.org/zap"
)

type AccountService interface {
	FindAccounts(ctx context.Context, filter *models.AccountFilter) ([]*models.Account, *models.Pagination, error)
	CreateAccount(ctx context.Context, tx pgx.Tx, request *models.NewAccount) (*models.Account, error)
	UpdateAccount(ctx context.Context, tx pgx.Tx, request *models.Account) (*models.Account, error)
	FindAdmins(ctx context.Context, filter *models.AccountFilter) ([]*models.Admin, *models.Pagination, error)
	CreateAdmin(ctx context.Context, tx pgx.Tx, request *models.NewAdmin) (*models.Admin, error)
	UpdateAdmin(ctx context.Context, tx pgx.Tx, request *models.Admin) (*models.Admin, error)
	FindUsers(ctx context.Context, filter *models.AccountFilter) ([]*models.User, *models.Pagination, error)
	CreateUser(ctx context.Context, tx pgx.Tx, request *models.NewUser) (*models.User, error)
	UpdateUser(ctx context.Context, tx pgx.Tx, request *models.User) (*models.User, error)
	ConsumeMessage(ctx context.Context, topic string, message []byte) error
}

type accountService struct {
	accountRepository repositories.AccountRepository
}

func NewAccountService(
	accountRepository repositories.AccountRepository,
) AccountService {
	return &accountService{
		accountRepository: accountRepository,
	}
}

func (q *accountService) FindAccounts(ctx context.Context, filter *models.AccountFilter) ([]*models.Account, *models.Pagination, error) {
	ctxt := "AccountService-FindAccounts"
	accounts, total, pages, err := q.accountRepository.FindAccounts(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return nil, nil, err
	}
	n := len(accounts)
	rows := make([]*models.Account, n)
	if n > 0 {
		copy(rows, accounts)
	}
	pagination, err := models.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *accountService) CreateAccount(ctx context.Context, tx pgx.Tx, request *models.NewAccount) (*models.Account, error) {
	ctxt := "AccountService-CreateAccount"
	response, err := q.accountRepository.CreateAccount(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateAccount")
	}
	return response, err
}

func (q *accountService) UpdateAccount(ctx context.Context, tx pgx.Tx, request *models.Account) (*models.Account, error) {
	ctxt := "AccountService-UpdateAccount"
	response, err := q.accountRepository.UpdateAccount(ctx, tx, request)
	if err != nil && !errors.Is(err, models.ErrAccountNotFound) {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
	}
	return response, err
}

func (q *accountService) FindAdmins(ctx context.Context, filter *models.AccountFilter) ([]*models.Admin, *models.Pagination, error) {
	ctxt := "AccountService-FindAdmins"
	filter.AccountTypes = []uint8{models.AccountTypeAdmin}
	admins, total, pages, err := q.accountRepository.FindAdmins(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return nil, nil, err
	}
	n := len(admins)
	rows := make([]*models.Admin, n)
	if n > 0 {
		copy(rows, admins)
	}
	pagination, err := models.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *accountService) CreateAdmin(ctx context.Context, tx pgx.Tx, request *models.NewAdmin) (*models.Admin, error) {
	ctxt := "AccountService-CreateAdmin"
	request.AccountType = models.AccountTypeAdmin
	response, err := q.accountRepository.CreateAdmin(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateAdmin")
	}
	return response, err
}

func (q *accountService) UpdateAdmin(ctx context.Context, tx pgx.Tx, request *models.Admin) (*models.Admin, error) {
	ctxt := "AccountService-UpdateAdmin"
	response, err := q.accountRepository.UpdateAdmin(ctx, tx, request)
	if err != nil && !errors.Is(err, models.ErrAccountNotFound) {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAdmin")
	}
	return response, err
}

func (q *accountService) FindUsers(ctx context.Context, filter *models.AccountFilter) ([]*models.User, *models.Pagination, error) {
	ctxt := "AccountService-FindUsers"
	filter.AccountTypes = []uint8{models.AccountTypeUser}
	users, total, pages, err := q.accountRepository.FindUsers(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindUsers")
		return nil, nil, err
	}
	n := len(users)
	rows := make([]*models.User, n)
	if n > 0 {
		copy(rows, users)
	}
	pagination, err := models.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *accountService) CreateUser(ctx context.Context, tx pgx.Tx, request *models.NewUser) (*models.User, error) {
	ctxt := "AccountService-CreateUser"
	request.AccountType = models.AccountTypeUser
	response, err := q.accountRepository.CreateUser(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateUser")
	}
	return response, err
}

func (q *accountService) UpdateUser(ctx context.Context, tx pgx.Tx, request *models.User) (*models.User, error) {
	ctxt := "AccountService-UpdateUser"
	response, err := q.accountRepository.UpdateUser(ctx, tx, request)
	if err != nil && !errors.Is(err, models.ErrAccountNotFound) {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateUser")
	}
	return response, err
}

func (q *accountService) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicAccount {
		return nil
	}
	return nil
}
