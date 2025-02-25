package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	storeModel "github.com/roysitumorang/sadia/modules/store/model"
)

type (
	StoreQuery interface {
		FindStores(ctx context.Context, filter *storeModel.Filter) ([]*storeModel.Store, int64, int64, error)
		CreateStore(ctx context.Context, request *storeModel.Store) (*storeModel.Store, error)
		UpdateStore(ctx context.Context, tx pgx.Tx, request *storeModel.Store) error
	}
)
