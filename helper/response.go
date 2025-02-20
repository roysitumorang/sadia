package helper

import (
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

const (
	APP = "sadia"
)

type (
	Response struct {
		RequestID  string      `json:"request_id" example:"6ba3451b-ac73-483e-8481-2ac53f5e75a2"`
		RequestURL string      `json:"request_url" example:"GET http://localhost:19000/ping"`
		StatusCode int         `json:"status_code" example:"200"`
		Status     string      `json:"status" example:"OK"`
		Message    string      `json:"message" example:""`
		Timestamp  time.Time   `json:"timestamp" example:"2025-02-05T12:22:47.608963985+07:00"`
		Latency    string      `json:"latency" example:"7.746177ms"`
		Data       interface{} `json:"data,omitempty"`
		App        string      `json:"app" example:"sadia"`
	}
)

func NewResponse(statusCode int) *Response {
	return &Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Timestamp:  time.Now(),
		App:        APP,
	}
}

func (r *Response) SetMessage(message string) *Response {
	r.Message = message
	return r
}

func (r *Response) SetData(data interface{}) *Response {
	r.Data = data
	return r
}

func (r *Response) WriteResponse(c *fiber.Ctx) error {
	if r.StatusCode == fiber.StatusNoContent {
		return c.SendStatus(r.StatusCode)
	}
	var builder strings.Builder
	_, _ = builder.WriteString(c.Method())
	_, _ = builder.WriteString(" ")
	_, _ = builder.WriteString(c.BaseURL())
	_, _ = builder.WriteString(c.OriginalURL())
	r.RequestURL = builder.String()
	r.RequestID = ByteSlice2String(c.Response().Header.Peek(fiber.HeaderXRequestID))
	r.Latency = time.Since(c.Context().Time()).String()
	return c.Status(r.StatusCode).JSON(r)
}
