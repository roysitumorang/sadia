package config

import (
	"time"
)

var (
	Version = "0.0.0"
	AppName,
	Commit,
	Build string
	Now = time.Now()
)
