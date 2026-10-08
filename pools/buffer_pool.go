package pools

import (
	"bytes"
	"sync"
)

var BufferPool = &bufferPool{
	pool: sync.Pool{
		New: func() any {
			return &bytes.Buffer{}
		},
	},
}

type bufferPool struct {
	pool sync.Pool
}

func (q *bufferPool) Get() *bytes.Buffer {
	return q.pool.Get().(*bytes.Buffer)
}

func (q *bufferPool) Put(buffer *bytes.Buffer) {
	q.pool.Put(buffer)
}

func (q *bufferPool) Reset() {
	q.Get().Reset()
}

func (q *bufferPool) WriteString(s string) (int, error) {
	return q.Get().WriteString(s)
}

func (q *bufferPool) Bytes() []byte {
	return q.Get().Bytes()
}
