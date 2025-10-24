package middleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
)

func UserSessionAuth(
	accountUseCase accountUseCase.AccountUseCase,
	userLevels ...uint8,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		ctx := c.Context()
		sess := session.FromContext(c)
		authenticated, authOk := sess.Get(models.Authenticated).(bool)
		userID, userOk := sess.Get(models.UserID).(string)
		if !authOk || !authenticated || !userOk || userID == "" {
			return c.Redirect().To("/account/login")
		}
		users, _, err := accountUseCase.FindUsers(
			ctx,
			accountModel.NewFilter(
				accountModel.WithAccountIDs(userID),
				accountModel.WithUserLevels(userLevels...),
			),
		)
		if err != nil || len(users) == 0 {
			return c.Redirect().To("/account/login")
		}
		currentUser := users[0]
		sess.Set(models.CurrentUser, currentUser)
		_ = sess.Session.Save()
		return c.Next()
	}
}
