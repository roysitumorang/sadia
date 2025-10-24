package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/roysitumorang/sadia/models"
	accountModel "github.com/roysitumorang/sadia/modules/account/model"
	accountUseCase "github.com/roysitumorang/sadia/modules/account/usecase"
)

func UserSessionAuth(
	sessionStore *session.Store,
	accountUseCase accountUseCase.AccountUseCase,
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
			return c.Redirect("/account/login")
		}
		currentUser := users[0]
		sess.Set(models.CurrentUser, currentUser)
		_ = sess.Save()
		return c.Next()
	}
}
