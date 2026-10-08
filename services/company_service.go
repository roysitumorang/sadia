package services

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/roysitumorang/sadia/helper"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/repositories"
	"go.uber.org/zap"
)

type CompanyService interface {
	FindCompanies(ctx context.Context, filter *models.CompanyFilter) ([]*models.Company, *models.Pagination, error)
	CreateCompany(ctx context.Context, tx pgx.Tx, request *models.NewCompany) (*models.Company, error)
	UpdateCompany(ctx context.Context, tx pgx.Tx, request *models.Company) error
	ConsumeMessage(ctx context.Context, topic string, message []byte) error
}

type companyService struct {
	companyRepository repositories.CompanyRepository
}

func NewCompanyService(
	companyRepository repositories.CompanyRepository,
) CompanyService {
	return &companyService{
		companyRepository: companyRepository,
	}
}

func (q *companyService) FindCompanies(ctx context.Context, filter *models.CompanyFilter) ([]*models.Company, *models.Pagination, error) {
	ctxt := "CompanyService-FindCompanies"
	companies, total, pages, err := q.companyRepository.FindCompanies(ctx, filter)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrFindCompanies")
		return nil, nil, err
	}
	n := len(companies)
	rows := make([]*models.Company, n)
	if n > 0 {
		copy(rows, companies)
	}
	pagination, err := models.SetPagination(total, pages, filter.Limit, filter.Page, filter.PaginationURL, filter.UrlValues)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrSetPagination")
		return nil, nil, err
	}
	return rows, pagination, nil
}

func (q *companyService) CreateCompany(ctx context.Context, tx pgx.Tx, request *models.NewCompany) (*models.Company, error) {
	ctxt := "CompanyService-CreateCompany"
	response, err := q.companyRepository.CreateCompany(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrCreateCompany")
	}
	return response, err
}

func (q *companyService) UpdateCompany(ctx context.Context, tx pgx.Tx, request *models.Company) error {
	ctxt := "CompanyService-UpdateCompany"
	err := q.companyRepository.UpdateCompany(ctx, tx, request)
	if err != nil {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrUpdateCompany")
	}
	return err
}

func (q *companyService) ConsumeMessage(ctx context.Context, topic string, message []byte) error {
	if topic != models.TopicCompany {
		return nil
	}
	return nil
}
