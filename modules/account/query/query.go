package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
)

type (
	AccountQuery interface {
		BeginTx(ctx context.Context) (pgx.Tx, error)
		FindAccounts(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.Account, int64, int64, error)
		UpdateAccount(ctx context.Context, tx pgx.Tx, request *accountModel.Account) error
	}
)
