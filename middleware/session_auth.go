package middleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/roysitumorang/sadia/models"
)

func UserSessionAuth() fiber.Handler {
	return func(c fiber.Ctx) error {
		sess := session.FromContext(c)
		authenticated, authOk := sess.Get(models.Authenticated).(bool)
		userID, userOk := sess.Get(models.UserID).(string)
		if !authOk || !authenticated || !userOk || userID == "" {
			return c.Redirect().To("/account/login")
		}
		return c.Next()
	}
}
