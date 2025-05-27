package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	companyQuery "github.com/roysitumorang/sadia/modules/company/query"
	"go.uber.org/zap"
)

type (
	companyUseCase struct {
		companyQuery companyQuery.CompanyQuery
	}
)

func New(
	companyQuery companyQuery.CompanyQuery,
) CompanyUseCase {
	return &companyUseCase{
		companyQuery: companyQuery,
	}
}

func (q *companyUseCase) FindCompanies(ctx context.Context, filter *companyModel.Filter) ([]*companyModel.Company, *models.Pagination, error) {
	ctxt := "CompanyUseCase-FindCompanies"
	companies, total, pages, err := q.companyQuery.FindCompanies(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return nil, nil, err
	}
	n := len(companies)
	rows := make([]*companyModel.Company, n)
	if n > 0 {
		copy(rows, companies)
	}
	pagination, err := helper.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *companyUseCase) CreateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.NewCompany) (*companyModel.Company, error) {
	ctxt := "CompanyUseCase-CreateCompany"
	response, err := q.companyQuery.CreateCompany(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateCompany")
	}
	return response, err
}

func (q *companyUseCase) UpdateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.Company) error {
	ctxt := "CompanyUseCase-UpdateCompany"
	err := q.companyQuery.UpdateCompany(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
	}
	return err
}

func (q *companyUseCase) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicCompany {
		return nil
	}
	return nil
}
