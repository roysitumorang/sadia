package usecase

import (
	"context"
	"net/url"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
)

type (
	AccountUseCase interface {
		BeginTx(ctx context.Context) (pgx.Tx, error)
		FindAccounts(ctx context.Context, filter *accountModel.Filter, urlValues url.Values) ([]*accountModel.Account, *models.Pagination, error)
		CreateAccount(ctx context.Context, tx pgx.Tx, request *accountModel.Account) error
		UpdateAccount(ctx context.Context, tx pgx.Tx, request *accountModel.Account) error
		ConsumeMessage(ctx context.Context) error
	}
)
