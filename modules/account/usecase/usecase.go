package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
)

type (
	AccountUseCase interface {
		FindAccounts(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.Account, *models.Pagination, error)
		CreateAccount(ctx context.Context, tx pgx.Tx, request *models.NewAccount) (*accountModel.Account, error)
		UpdateAccount(ctx context.Context, tx pgx.Tx, request *accountModel.Account) error
		FindAdmins(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.Admin, *models.Pagination, error)
		CreateAdmin(ctx context.Context, tx pgx.Tx, request *accountModel.NewAdmin) (*accountModel.Admin, error)
		UpdateAdmin(ctx context.Context, tx pgx.Tx, request *accountModel.Admin) error
		FindUsers(ctx context.Context, filter *accountModel.Filter) ([]*accountModel.User, *models.Pagination, error)
		CreateUser(ctx context.Context, tx pgx.Tx, request *accountModel.NewUser) (*accountModel.User, error)
		UpdateUser(ctx context.Context, tx pgx.Tx, request *accountModel.User) error
		ConsumeMessage(ctx context.Context) error
	}
)
