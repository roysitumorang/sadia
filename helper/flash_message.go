package helper

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"go.uber.org/zap"
)

type (
	FlashMessage struct {
		Data map[string]string
	}
)

const (
	Flash = "flash"
)

func NewFlashMessage() *FlashMessage {
	return &FlashMessage{
		Data: map[string]string{},
	}
}

func (f *FlashMessage) Danger(message string) *FlashMessage {
	f.Data["danger"] = message
	return f
}

func (f *FlashMessage) Success(message string) *FlashMessage {
	f.Data["success"] = message
	return f
}

func (f *FlashMessage) Warning(message string) *FlashMessage {
	f.Data["warning"] = message
	return f
}

func (f *FlashMessage) Info(message string) *FlashMessage {
	f.Data["info"] = message
	return f
}

func (f *FlashMessage) Redirect(c fiber.Ctx, sess *session.Session, location string, statusCode ...int) error {
	ctx := c.Context()
	ctxt := "FlashMessage-Redirect"
	sess.Set(Flash, f)
	if err := sess.Save(); err != nil {
		Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrSave")
	}
	redirect := c.Redirect()
	if len(statusCode) > 0 {
		redirect = redirect.Status(statusCode[0])
	}
	return redirect.To(location)
}

func (f *FlashMessage) Clear(c fiber.Ctx, sess *session.Session) *FlashMessage {
	ctx := c.Context()
	ctxt := "FlashMessage-Clear"
	f.Data = map[string]string{}
	sess.Set(Flash, f)
	if err := sess.Save(); err != nil {
		Capture(ctx, zap.ErrorLevel, err, ctxt, "ErrSave")
	}
	return f
}
