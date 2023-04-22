package pool

import "sync"

// 长度 51 小对象
var byte51Pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 51)
		return &b
	},
}

func GetByte51() *[]byte {
	b := byte51Pool.Get().(*[]byte)
	return b
}

func PutByte51(b *[]byte) {
	*b = (*b)[:51]
	byte51Pool.Put(b)
}
