package model

import (
	"time"
)

type (
	Sequence struct {
		ID        int64     `json:"-"`
		Name      string    `json:"-"`
		Number    uint32    `json:"-"`
		CreatedBy int64     `json:"-"`
		CreatedAt time.Time `json:"-"`
		UpdatedBy int64     `json:"-"`
		UpdatedAt time.Time `json:"-"`
	}
)
