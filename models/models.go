package models

const (
	CurrentAccount = "current_account"
)

type (
	Pagination struct {
		Links struct {
			First    string `json:"first" example:"http://localhost:19000/v1/cities?limit=1&search=Tangerang"`
			Previous string `json:"previous" example:"http://localhost:19000/v1/cities?limit=1&search=Tangerang"`
			Current  string `json:"current" example:"http://localhost:19000/v1/cities?limit=1&page=2&search=Tangerang"`
			Next     string `json:"next" example:"http://localhost:19000/v1/cities?limit=1&page=3&search=Tangerang"`
		} `json:"links"`
		Info struct {
			Limit int64 `json:"limit" example:"1"`
			Pages int64 `json:"pages" example:"3"`
			Total int64 `json:"total" example:"3"`
		} `json:"info"`
	}

	Message struct {
		Action string `json:"action"`
		ID     int64  `json:"id"`
	}
)

var (
	MapLimits = map[int]int{1: 1, 10: 1, 25: 1, 50: 1, 100: 1}
	Limits    = []int{1, 10, 25, 50, 100}
)
