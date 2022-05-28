package utils

import (
	"bytes"
	"encoding/base64"
	"github.com/spaolacci/murmur3"
)

// Mmh3Hash32 计算 mmh3 hash
func Mmh3Hash32(raw []byte) int32 {
	h32 := murmur3.New32()
	h32.Write(raw)
	return int32(h32.Sum32())
}

// base64 encode
func Base64Encode(raw []byte) []byte {
	data := base64.StdEncoding.EncodeToString(raw)
	var buffer bytes.Buffer
	for i := 0; i < len(data); i++ {
		ch := data[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
