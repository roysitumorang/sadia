package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
	companyModel "github.com/roysitumorang/sadia/modules/company/model"
	companyUseCase "github.com/roysitumorang/sadia/modules/company/usecase"
	sessionModel "github.com/roysitumorang/sadia/modules/session/model"
	sessionUseCase "github.com/roysitumorang/sadia/modules/session/usecase"
)

func UserSessionAuth(
	sessionStore *session.Store,
	accountUseCase accountUseCase.AccountUseCase,
	companyUseCase companyUseCase.CompanyUseCase,
	sessionUseCase sessionUseCase.SessionUseCase,
	userLevels ...uint8,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.Context()
		sess, err := sessionStore.Get(c)
		if err != nil {
			return c.Redirect("/account/login")
		}
		authenticated, authOk := sess.Get(models.Authenticated).(bool)
		userID, userOk := sess.Get(models.UserID).(string)
		if !authOk || !authenticated || !userOk || userID == "" {
			return c.Redirect("/account/login")
		}
		users, _, err := accountUseCase.FindUsers(
			ctx,
			accountModel.NewFilter(
				accountModel.WithAccountIDs(userID),
				accountModel.WithUserLevels(userLevels...),
			),
		)
		if err != nil || len(users) == 0 {
			sess.Reset()
			_ = sess.Save()
			return c.Redirect("/account/login")
		}
		currentUser := users[0]
		sess.Set(models.CurrentUser, currentUser)
		companies, _, err := companyUseCase.FindCompanies(
			ctx,
			companyModel.NewFilter(
				companyModel.WithCompanyIDs(currentUser.CompanyID),
			),
		)
		if err != nil || len(companies) == 0 {
			sess.Reset()
			_ = sess.Save()
			return c.Redirect("/account/login")
		}
		currentCompany := companies[0]
		sess.Set(models.CurrentCompany, currentCompany)
		if currentCompany.SessionID != nil {
			sessions, _, err := sessionUseCase.FindSessions(
				ctx,
				sessionModel.NewFilter(
					sessionModel.WithSessionIDs(*currentCompany.SessionID),
				),
			)
			if err != nil || len(sessions) == 0 {
				sess.Reset()
				_ = sess.Save()
				return c.Redirect("/account/login")
			}
			sess.Set(models.CurrentSession, sessions[0])
		}
		_ = sess.Save()
		return c.Next()
	}
}
