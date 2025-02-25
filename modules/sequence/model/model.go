package model

import (
	"time"
)

type (
	Sequence struct {
		ID        string    `json:"-"`
		Name      string    `json:"-"`
		Number    uint32    `json:"-"`
		CreatedBy string    `json:"-"`
		CreatedAt time.Time `json:"-"`
		UpdatedBy string    `json:"-"`
		UpdatedAt time.Time `json:"-"`
	}
)
