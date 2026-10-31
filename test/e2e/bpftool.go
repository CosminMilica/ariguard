//go:build e2e

package e2e

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// bpfEntry is one element of a `bpftool map dump -j` array. bpftool renders the
// key/value either as a byte array (["0x03",...]) or, when the map carries BTF,
// as a formatted object/number ({"num_rules":3,...}). Both forms are handled.
type bpfEntry struct {
	Key    json.RawMessage `json:"key"`
	Value  json.RawMessage `json:"value"`
	Values json.RawMessage `json:"values"` // per-CPU maps; unused here
}

// parseMapDump decodes the JSON from `bpftool map dump name <m> -j`.
func parseMapDump(b []byte) ([]bpfEntry, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("empty bpftool output")
	}
	if b[0] == '[' {
		var entries []bpfEntry
		if err := json.Unmarshal(b, &entries); err != nil {
			return nil, err
		}
		return entries, nil
	}
	// Some bpftool versions wrap the elements in an object; take the first array.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, err
	}
	for _, v := range obj {
		if len(v) > 0 && bytes.TrimSpace(v)[0] == '[' {
			var entries []bpfEntry
			if err := json.Unmarshal(v, &entries); err == nil {
				return entries, nil
			}
		}
	}
	return nil, fmt.Errorf("no element array in bpftool output: %s", string(b))
}

// rawBytes decodes a value rendered as a flat byte array; ok is false for a
// formatted object or scalar.
func rawBytes(raw json.RawMessage) ([]byte, bool) {
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, false
	}
	out := make([]byte, 0, len(arr))
	for _, v := range arr {
		switch x := v.(type) {
		case string:
			n, err := strconv.ParseUint(strings.TrimPrefix(x, "0x"), 16, 8)
			if err != nil {
				if n, err = strconv.ParseUint(x, 10, 8); err != nil {
					return nil, false
				}
			}
			out = append(out, byte(n))
		case float64:
			out = append(out, byte(int64(x)))
		default:
			return nil, false
		}
	}
	return out, true
}

// policyFields reads AG_POLICY[0] as (num_rules, enforce), from either the byte
// or the formatted representation.
func policyFields(e bpfEntry) (numRules, enforce uint32, err error) {
	if b, ok := rawBytes(e.Value); ok && len(b) >= 8 {
		return binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint32(b[4:8]), nil
	}
	var m map[string]json.Number
	if err := json.Unmarshal(e.Value, &m); err != nil {
		return 0, 0, fmt.Errorf("decode AG_POLICY value %s: %w", string(e.Value), err)
	}
	nr, _ := m["num_rules"].Int64()
	en, _ := m["enforce"].Int64()
	return uint32(nr), uint32(en), nil
}

// jsonAllZero reports whether every numeric leaf of a bpftool value is zero,
// handling both byte arrays and formatted structs. For an ARRAY map this tells a
// zeroed slot apart from a populated one; "non-empty" means some slot is non-zero.
func jsonAllZero(raw json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return allZero(v)
}

func allZero(v any) bool {
	switch x := v.(type) {
	case float64:
		return x == 0
	case string:
		s := strings.TrimPrefix(x, "0x")
		n, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			if n, err = strconv.ParseUint(x, 10, 64); err != nil {
				return x == "" // non-numeric string: treat as padding
			}
		}
		return n == 0
	case []any:
		for _, e := range x {
			if !allZero(e) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, e := range x {
			if !allZero(e) {
				return false
			}
		}
		return true
	case bool:
		return !x
	case nil:
		return true
	default:
		return false
	}
}

// nonZeroEntries counts map elements whose value is not all-zero.
func nonZeroEntries(entries []bpfEntry) int {
	n := 0
	for _, e := range entries {
		if !jsonAllZero(e.Value) {
			n++
		}
	}
	return n
}
