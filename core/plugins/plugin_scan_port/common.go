package plugin_scan_port

import (
	"regexp"
	"strconv"
)

// 判断16进制字符串
func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

// 判断8进制字符串
func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

// 判断结构字符串
func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

// 判断正则字符串
func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

// 其他转义字符串
func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

// 解析指纹库中匹配规则字符串，转换成 golang 中可以进行编译的字符串
func DecodePattern(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		// 十六进制转义格式
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
		}
		// 格式控制符 \r\n\a\b\f\t
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  {0x07}, // \a
				102: {0x0c}, // \f
				116: {0x09}, // \t
				110: {0x0a}, // \n
				114: {0x0d}, // \r
				118: {0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		// 八进制转义格式
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

// 解码数据
func DecodeData(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		// 十六进制转义格式
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			replace = []byte{uint8(byteNum)}
		}
		// 格式控制符 \r\n\a\b\f\t
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  {0x07}, // \a
				102: {0x0c}, // \f
				116: {0x09}, // \t
				110: {0x0a}, // \n
				114: {0x0d}, // \r
				118: {0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		// 八进制转义格式
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}
