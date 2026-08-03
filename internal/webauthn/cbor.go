package webauthn

import (
	"encoding/binary"
	"errors"
	"math"
)

// 最小 CBOR 解码器(RFC 8949 子集),仅覆盖 WebAuthn 所需:
// 无符号/负整数、字节串、文本串、数组、映射与 false/true/null。
// 不支持 tag、浮点与不定长编码。

const (
	maxCBORDepth = 8
	maxCBORItems = 1 << 14
)

var errCBOR = errors.New("cbor 数据格式错误")

type cborDecoder struct {
	data  []byte
	pos   int
	items int
}

// decodeCBOR 解析 data 开头的一个 CBOR 值,返回值与消耗的字节数。
func decodeCBOR(data []byte) (any, int, error) {
	d := &cborDecoder{data: data}
	v, err := d.decode(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

func (d *cborDecoder) readByte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, errCBOR
	}
	b := d.data[d.pos]
	d.pos++
	return b, nil
}

func (d *cborDecoder) readN(n uint64) ([]byte, error) {
	if n > uint64(len(d.data)-d.pos) {
		return nil, errCBOR
	}
	b := d.data[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return b, nil
}

// readArg 读取首字节附加信息对应的参数值。
func (d *cborDecoder) readArg(info byte) (uint64, error) {
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		b, err := d.readByte()
		return uint64(b), err
	case info == 25:
		b, err := d.readN(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(b)), nil
	case info == 26:
		b, err := d.readN(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(b)), nil
	case info == 27:
		b, err := d.readN(8)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(b), nil
	default:
		// 28-30 保留,31 不定长:均不支持
		return 0, errors.New("cbor: 不支持的长度编码")
	}
}

func (d *cborDecoder) decode(depth int) (any, error) {
	if depth > maxCBORDepth {
		return nil, errors.New("cbor: 嵌套过深")
	}
	d.items++
	if d.items > maxCBORItems {
		return nil, errors.New("cbor: 元素过多")
	}
	ib, err := d.readByte()
	if err != nil {
		return nil, err
	}
	major := ib >> 5
	arg, err := d.readArg(ib & 0x1f)
	if err != nil {
		return nil, err
	}

	switch major {
	case 0: // 无符号整数
		if arg > math.MaxInt64 {
			return nil, errCBOR
		}
		return int64(arg), nil
	case 1: // 负整数 -1-arg
		if arg > math.MaxInt64-1 {
			return nil, errCBOR
		}
		return -1 - int64(arg), nil
	case 2: // 字节串
		b, err := d.readN(arg)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(b))
		copy(out, b)
		return out, nil
	case 3: // 文本串
		b, err := d.readN(arg)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case 4: // 数组
		if arg > uint64(len(d.data)-d.pos) {
			return nil, errCBOR
		}
		out := make([]any, 0, int(arg))
		for i := uint64(0); i < arg; i++ {
			v, err := d.decode(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5: // 映射,键限定为整数或字符串
		if arg > uint64(len(d.data)-d.pos) {
			return nil, errCBOR
		}
		out := make(map[any]any, int(arg))
		for i := uint64(0); i < arg; i++ {
			k, err := d.decode(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, errors.New("cbor: 不支持的映射键类型")
			}
			v, err := d.decode(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 7: // 简单值
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, errors.New("cbor: 不支持的简单值")
	default: // 6 tag
		return nil, errors.New("cbor: 不支持 tag")
	}
}
