package query

import (
	"context"

	"github.com/jackc/pgx/v5"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
)

type (
	CompanyQuery interface {
		FindCompanies(ctx context.Context, filter *companyModel.Filter) ([]*companyModel.Company, int64, int64, error)
		CreateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.NewCompany) (*companyModel.Company, error)
		UpdateCompany(ctx context.Context, tx pgx.Tx, request *companyModel.Company) error
	}
)
