package pools

import (
	"strings"
	"sync"
)

var BuilderPool = &builderPool{
	pool: sync.Pool{
		New: func() any {
			return &strings.Builder{}
		},
	},
}

type builderPool struct {
	pool sync.Pool
}

func (q *builderPool) Get() *strings.Builder {
	return q.pool.Get().(*strings.Builder)
}

func (q *builderPool) Put(builder *strings.Builder) {
	q.pool.Put(builder)
}

func (q *builderPool) Reset() {
	q.Get().Reset()
}

func (q *builderPool) WriteString(s string) (int, error) {
	return q.Get().WriteString(s)
}

func (q *builderPool) String() string {
	return q.Get().String()
}
