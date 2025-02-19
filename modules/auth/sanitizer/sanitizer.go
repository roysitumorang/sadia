package sanitizer

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/roysitumorang/sadia/helper"
	authModel "github.com/roysitumorang/sadia/modules/auth/model"
	"go.uber.org/zap"
)

func Login(ctx context.Context, c *fiber.Ctx) (*authModel.LoginRequest, int, error) {
	ctxt := "AuthSanitizer-Login"
	var response authModel.LoginRequest
	err := c.BodyParser(&response)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		helper.Log(ctx, zap.ErrorLevel, err.Error(), ctxt, "ErrBodyParser")
		return nil, fiberErr.Code, err
	}
	return &response, fiber.StatusOK, nil
}
