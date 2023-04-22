package utils

import (
	"sync"
)

// 不允许直接修改
// [6] => PType
var plHeader = []byte{
	'S', 'T', 'F', 1,
	0x00, 0x00, /* Length */
	0x00, /* Type */
	0x00, /* Unknown */
}

// 长度 34 小对象
var byte34Pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 34)
		return &b
	},
}

func getByte34() *[]byte {
	b := byte34Pool.Get().(*[]byte)
	return b
}

func putByte34(b *[]byte) {
	*b = (*b)[:34]
	byte34Pool.Put(b)
}

type BufferPool struct {
	sync.Pool
}

func getByte51() *[]byte {
	b := byte51Pool.Get().(*[]byte)
	return b
}

// 长度 51 小对象
var byte51Pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 51)
		return &b
	},
}

func putByte51(b *[]byte) {
	*b = (*b)[:51]
	byte51Pool.Put(b)
}
