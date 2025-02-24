package usecase

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/models"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
)

type (
	CompanyUseCase interface {
		FindCompanies(ctx context.Context, filter *companyModel.Filter) ([]*companyModel.Company, *models.Pagination, error)
		CreateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.NewCompany) (*companyModel.Company, error)
		UpdateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.Company) error
		ConsumeMessage(ctx context.Context) error
	}
)
