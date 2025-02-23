package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
)

type (
	AccountQuery interface {
		FindAccounts(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.Account, int64, int64, error)
		CreateAccount(ctx context.Context, request *accountModel.NewAccount) (*accountModel.Account, error)
		UpdateAccount(ctx context.Context, tx pgx.Tx, request *accountModel.Account) error
	}
)
