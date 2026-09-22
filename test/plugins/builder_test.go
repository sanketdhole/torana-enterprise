package plugins_test

import (
	"bytes"
)

// WasmBytecodeBuilder builds minimal, valid WebAssembly binaries for tests.
type WasmBytecodeBuilder struct {
	types   [][]byte
	imports [][]byte
	funcs   []uint32 // type indices
	memories [][]byte
	exports [][]byte
	codes   [][]byte
	data    [][]byte
}

func NewWasmBuilder() *WasmBytecodeBuilder {
	return &WasmBytecodeBuilder{}
}

func encodeUleb128(v uint32) []byte {
	var res []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		res = append(res, b)
		if v == 0 {
			break
		}
	}
	return res
}

func encodeIleb128(v int64) []byte {
	var res []byte
	more := true
	for more {
		b := byte(v & 0x7F)
		v >>= 7
		signBit := (b & 0x40) != 0
		if (v == 0 && !signBit) || (v == -1 && signBit) {
			more = false
		} else {
			b |= 0x80
		}
		res = append(res, b)
	}
	return res
}

// AddType adds a function signature: param types and result types.
// e.g. i32 = 0x7F, i64 = 0x7E
func (b *WasmBytecodeBuilder) AddType(params []byte, results []byte) uint32 {
	var t []byte
	t = append(t, 0x60) // func type tag
	t = append(t, encodeUleb128(uint32(len(params)))...)
	t = append(t, params...)
	t = append(t, encodeUleb128(uint32(len(results)))...)
	t = append(t, results...)
	b.types = append(b.types, t)
	return uint32(len(b.types) - 1)
}

// AddImport adds a function import.
func (b *WasmBytecodeBuilder) AddImport(module, field string, typeIdx uint32) uint32 {
	var imp []byte
	imp = append(imp, encodeUleb128(uint32(len(module)))...)
	imp = append(imp, []byte(module)...)
	imp = append(imp, encodeUleb128(uint32(len(field)))...)
	imp = append(imp, []byte(field)...)
	imp = append(imp, 0x00) // export_desc: func
	imp = append(imp, encodeUleb128(typeIdx)...)
	b.imports = append(b.imports, imp)
	return uint32(len(b.imports) - 1)
}

// AddMemory adds linear memory declaration (initial pages, optional max pages).
func (b *WasmBytecodeBuilder) AddMemory(initial uint32, max *uint32) {
	var m []byte
	if max == nil {
		m = append(m, 0x00) // limits: min only
		m = append(m, encodeUleb128(initial)...)
	} else {
		m = append(m, 0x01) // limits: min and max
		m = append(m, encodeUleb128(initial)...)
		m = append(m, encodeUleb128(*max)...)
	}
	b.memories = append(b.memories, m)
}

// AddFunction adds a defined function with its type index and bytecode body.
func (b *WasmBytecodeBuilder) AddFunction(typeIdx uint32, bodyInstructions []byte) uint32 {
	b.funcs = append(b.funcs, typeIdx)

	var code []byte
	code = append(code, 0x00) // 0 local declarations
	code = append(code, bodyInstructions...)
	code = append(code, 0x0B) // end opcode

	var fullCode []byte
	fullCode = append(fullCode, encodeUleb128(uint32(len(code)))...)
	fullCode = append(fullCode, code...)
	b.codes = append(b.codes, fullCode)

	return uint32(len(b.imports) + len(b.funcs) - 1)
}

// AddExport exports a function or memory. kind: 0 = func, 2 = memory.
func (b *WasmBytecodeBuilder) AddExport(name string, kind byte, index uint32) {
	var exp []byte
	exp = append(exp, encodeUleb128(uint32(len(name)))...)
	exp = append(exp, []byte(name)...)
	exp = append(exp, kind)
	exp = append(exp, encodeUleb128(index)...)
	b.exports = append(b.exports, exp)
}

// AddDataSegment places static bytes at a constant linear memory offset.
func (b *WasmBytecodeBuilder) AddDataSegment(offset uint32, data []byte) {
	var seg []byte
	seg = append(seg, 0x00) // active segment memory index 0
	seg = append(seg, 0x41) // i32.const
	seg = append(seg, encodeIleb128(int64(offset))...)
	seg = append(seg, 0x0B) // end
	seg = append(seg, encodeUleb128(uint32(len(data)))...)
	seg = append(seg, data...)
	b.data = append(b.data, seg)
}

// Build generates the final .wasm binary.
func (b *WasmBytecodeBuilder) Build() []byte {
	var buf bytes.Buffer
	// Magic & Version
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00})

	// Section 1: Type
	if len(b.types) > 0 {
		var sec bytes.Buffer
		sec.Write(encodeUleb128(uint32(len(b.types))))
		for _, t := range b.types {
			sec.Write(t)
		}
		buf.WriteByte(1)
		buf.Write(encodeUleb128(uint32(sec.Len())))
		buf.Write(sec.Bytes())
	}

	// Section 2: Import
	if len(b.imports) > 0 {
		var sec bytes.Buffer
		sec.Write(encodeUleb128(uint32(len(b.imports))))
		for _, imp := range b.imports {
			sec.Write(imp)
		}
		buf.WriteByte(2)
		buf.Write(encodeUleb128(uint32(sec.Len())))
		buf.Write(sec.Bytes())
	}

	// Section 3: Function
	if len(b.funcs) > 0 {
		var sec bytes.Buffer
		sec.Write(encodeUleb128(uint32(len(b.funcs))))
		for _, f := range b.funcs {
			sec.Write(encodeUleb128(f))
		}
		buf.WriteByte(3)
		buf.Write(encodeUleb128(uint32(sec.Len())))
		buf.Write(sec.Bytes())
	}

	// Section 5: Memory
	if len(b.memories) > 0 {
		var sec bytes.Buffer
		sec.Write(encodeUleb128(uint32(len(b.memories))))
		for _, m := range b.memories {
			sec.Write(m)
		}
		buf.WriteByte(5)
		buf.Write(encodeUleb128(uint32(sec.Len())))
		buf.Write(sec.Bytes())
	}

	// Section 7: Export
	if len(b.exports) > 0 {
		var sec bytes.Buffer
		sec.Write(encodeUleb128(uint32(len(b.exports))))
		for _, exp := range b.exports {
			sec.Write(exp)
		}
		buf.WriteByte(7)
		buf.Write(encodeUleb128(uint32(sec.Len())))
		buf.Write(sec.Bytes())
	}

	// Section 10: Code
	if len(b.codes) > 0 {
		var sec bytes.Buffer
		sec.Write(encodeUleb128(uint32(len(b.codes))))
		for _, c := range b.codes {
			sec.Write(c)
		}
		buf.WriteByte(10)
		buf.Write(encodeUleb128(uint32(sec.Len())))
		buf.Write(sec.Bytes())
	}

	// Section 11: Data
	if len(b.data) > 0 {
		var sec bytes.Buffer
		sec.Write(encodeUleb128(uint32(len(b.data))))
		for _, d := range b.data {
			sec.Write(d)
		}
		buf.WriteByte(11)
		buf.Write(encodeUleb128(uint32(sec.Len())))
		buf.Write(sec.Bytes())
	}

	return buf.Bytes()
}
