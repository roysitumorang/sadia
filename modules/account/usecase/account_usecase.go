package usecase

import (
	"context"
	"net/url"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountQuery "github.com/roysitumorang/sadia/modules/account/query"
	"go.uber.org/zap"
)

type (
	accountUseCase struct {
		accountQuery accountQuery.AccountQuery
	}
)

func New(
	accountQuery accountQuery.AccountQuery,
) AccountUseCase {
	return &accountUseCase{
		accountQuery: accountQuery,
	}
}

func (q *accountUseCase) BeginTx(ctx context.Context) (pgx.Tx, error) {
	ctxt := "AccountUseCase-BeginTx"
	tx, err := q.accountQuery.BeginTx(ctx)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBeginTx")
	}
	return tx, err
}

func (q *accountUseCase) FindAccounts(ctx context.Context, filter *accountModel.Filter, urlValues url.Values) ([]*accountModel.Account, *models.Pagination, error) {
	ctxt := "AccountUseCase-FindAccounts"
	rows, total, pages, err := q.accountQuery.FindAccounts(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindAccounts")
		return nil, nil, err
	}
	pagination, err := helper.SetPagination(total, pages, filter.PerPage, filter.Page, filter.PaginationURL, urlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *accountUseCase) UpdateAccount(ctx context.Context, tx pgx.Tx, request *accountModel.Account) error {
	ctxt := "AccountUseCase-UpdateAccount"
	err := q.accountQuery.UpdateAccount(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateAccount")
	}
	return err
}
