package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	storeModel "github.com/roysitumorang/sadia/modules/store/model"
	storeQuery "github.com/roysitumorang/sadia/modules/store/query"
	"go.uber.org/zap"
)

type (
	storeUseCase struct {
		storeQuery storeQuery.StoreQuery
	}
)

func New(
	storeQuery storeQuery.StoreQuery,
) StoreUseCase {
	return &storeUseCase{
		storeQuery: storeQuery,
	}
}

func (q *storeUseCase) FindStores(ctx context.Context, filter *storeModel.Filter) ([]*storeModel.Store, *models.Pagination, error) {
	ctxt := "StoreUseCase-FindStores"
	storeCategories, total, pages, err := q.storeQuery.FindStores(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindStores")
		return nil, nil, err
	}
	n := len(storeCategories)
	rows := make([]*storeModel.Store, n)
	if n > 0 {
		copy(rows, storeCategories)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *storeUseCase) CreateStore(ctx context.Context, request *storeModel.Store) (*storeModel.Store, error) {
	ctxt := "StoreUseCase-CreateStore"
	response, err := q.storeQuery.CreateStore(ctx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateStore")
	}
	return response, err
}

func (q *storeUseCase) UpdateStore(ctx context.Context, tx pgx.Tx, request *storeModel.Store) error {
	ctxt := "StoreUseCase-UpdateStore"
	err := q.storeQuery.UpdateStore(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateStore")
	}
	return err
}

func (q *storeUseCase) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicStore {
		return nil
	}
	return nil
}
