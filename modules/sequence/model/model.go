package model

import (
	"time"
)

type (
	Sequence struct {
		ID        uint64    `json:"-"`
		Name      string    `json:"-"`
		Number    uint32    `json:"-"`
		CreatedBy uint64    `json:"-"`
		CreatedAt time.Time `json:"-"`
		UpdatedBy uint64    `json:"-"`
		UpdatedAt time.Time `json:"-"`
	}
)
