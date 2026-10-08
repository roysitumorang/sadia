package middleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/roysitumorang/sadia/models"
	"github.com/roysitumorang/sadia/services"
)

func UserSessionAuth(
	accountService services.AccountService,
	companyService services.CompanyService,
	sessionService services.SessionService,
	userLevels ...uint8,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		ctx := c.Context()
		sess := session.FromContext(c)
		authenticated, authOk := sess.Get(models.Authenticated).(bool)
		userID, userOk := sess.Get(models.UserID).(uint64)
		if !authOk || !authenticated || !userOk || userID == 0 {
			return c.Redirect().To("/account/login")
		}
		users, _, err := accountService.FindUsers(
			ctx,
			models.NewAccountFilter(
				models.AccountWithAccountIDs(userID),
				models.AccountWithUserLevels(userLevels...),
			),
		)
		if err != nil || len(users) == 0 {
			_ = sess.Reset()
			_ = sess.Session.Save()
			return c.Redirect().To("/account/login")
		}
		currentUser := users[0]
		sess.Set(models.CurrentUser, currentUser)
		companies, _, err := companyService.FindCompanies(
			ctx,
			models.NewCompanyFilter(
				models.CompanyWithCompanyIDs(currentUser.CompanyID),
			),
		)
		if err != nil || len(companies) == 0 {
			_ = sess.Reset()
			_ = sess.Session.Save()
			return c.Redirect().To("/account/login")
		}
		currentCompany := companies[0]
		sess.Set(models.CurrentCompany, currentCompany)
		if currentCompany.SessionID != nil {
			sessions, _, err := sessionService.FindSessions(
				ctx,
				models.NewSessionFilter(
					models.SessionWithSessionIDs(*currentCompany.SessionID),
				),
			)
			if err != nil || len(sessions) == 0 {
				_ = sess.Reset()
				_ = sess.Session.Save()
				return c.Redirect().To("/account/login")
			}
			sess.Set(models.CurrentSession, sessions[0])
		}
		cart, ok := sess.Get(models.CurrentCart).(*models.Transaction)
		if !ok {
			cart = &models.Transaction{
				LineItems: []*models.LineItem{},
			}
		}
		sess.Set(models.CurrentCart, cart)
		_ = sess.Session.Save()
		return c.Next()
	}
}
