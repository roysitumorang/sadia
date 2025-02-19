package errors

type (
	customError interface {
		Code() int
		Error() string
	}

	customErrorString struct {
		c int
		s string
	}
)

func New(c int, s string) customError {
	return &customErrorString{
		c: c,
		s: s,
	}
}

func (e *customErrorString) Code() int {
	return e.c
}

func (e *customErrorString) Error() string {
	return e.s
}
