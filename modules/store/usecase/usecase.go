package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	storeModel "github.com/roysitumorang/sadia/modules/store/model"
)

type (
	StoreUseCase interface {
		FindStores(ctx context.Context, filter *storeModel.Filter) ([]*storeModel.Store, *models.Pagination, error)
		CreateStore(ctx context.Context, request *storeModel.Store) (*storeModel.Store, error)
		UpdateStore(ctx context.Context, tx pgx.Tx, request *storeModel.Store) error
		ConsumeMessage(ctx context.Context) error
	}
)
