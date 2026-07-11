package managedkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"unicode/utf8"
)

const (
	maxExactJSONDepth   = 128
	maxExactJSONEntries = 100_000
)

type exactJSONParser struct {
	decoder *json.Decoder
	depth   int
	entries int
}

func decodeExactJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("canonical string domain requires valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	parser := exactJSONParser{decoder: decoder}
	value, err := parser.value()
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("invalid JSON trailing data")
		}
		return nil, err
	}
	return value, nil
}

func (parser *exactJSONParser) recordEntry() error {
	parser.entries++
	if parser.entries > maxExactJSONEntries {
		return errors.New("JSON entry limit exceeded")
	}
	return nil
}

func (parser *exactJSONParser) value() (any, error) {
	token, err := parser.decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		if text, ok := token.(string); ok {
			if err := validateCanonicalString(text); err != nil {
				return nil, err
			}
		}
		return token, nil
	}
	parser.depth++
	if parser.depth > maxExactJSONDepth {
		return nil, errors.New("JSON nesting limit exceeded")
	}
	defer func() { parser.depth-- }()
	switch delimiter {
	case '{':
		object := map[string]any{}
		for parser.decoder.More() {
			if err := parser.recordEntry(); err != nil {
				return nil, err
			}
			keyToken, err := parser.decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid JSON object key")
			}
			if err := validateCanonicalString(key); err != nil {
				return nil, err
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON key: %s", key)
			}
			value, err := parser.value()
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := parser.decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid JSON object")
		}
		return object, nil
	case '[':
		array := []any{}
		for parser.decoder.More() {
			if err := parser.recordEntry(); err != nil {
				return nil, err
			}
			value, err := parser.value()
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := parser.decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid JSON array")
		}
		return array, nil
	default:
		return nil, errors.New("invalid JSON delimiter")
	}
}

func exactObject(value any, fields []string, label string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(fields) {
		return nil, fmt.Errorf("%s fields invalid", label)
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return nil, fmt.Errorf("%s fields invalid", label)
		}
	}
	return object, nil
}

func exactString(value any, label string) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" {
		return "", fmt.Errorf("%s invalid", label)
	}
	if err := validateCanonicalString(text); err != nil {
		return "", err
	}
	return text, nil
}

func exactInteger(value any, label string) (int, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s invalid", label)
	}
	integer, err := strconv.ParseInt(string(number), 10, 64)
	if err != nil || integer < math.MinInt || integer > math.MaxInt || integer < -9007199254740991 || integer > 9007199254740991 {
		return 0, fmt.Errorf("%s invalid", label)
	}
	return int(integer), nil
}

func validateCanonicalString(value string) error {
	if !utf8.ValidString(value) {
		return errors.New("canonical string domain requires valid UTF-8")
	}
	for _, character := range value {
		if character == '\u2028' || character == '\u2029' {
			return errors.New("canonical string domain excludes U+2028/U+2029")
		}
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	if err := appendCanonicalJSON(&buffer, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func appendCanonicalJSON(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case string:
		if err := validateCanonicalString(typed); err != nil {
			return err
		}
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(typed); err != nil {
			return err
		}
		buffer.Write(bytes.TrimSuffix(encoded.Bytes(), []byte("\n")))
	case json.Number:
		text := string(typed)
		if _, err := strconv.ParseInt(text, 10, 64); err != nil {
			return errors.New("canonical JSON integer invalid")
		}
		buffer.WriteString(text)
	case int:
		buffer.WriteString(strconv.Itoa(typed))
	case bool:
		buffer.WriteString(strconv.FormatBool(typed))
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := appendCanonicalJSON(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if err := validateCanonicalString(key); err != nil {
				return err
			}
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left, right int) bool { return bytes.Compare([]byte(keys[left]), []byte(keys[right])) < 0 })
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := appendCanonicalJSON(buffer, key); err != nil {
				return err
			}
			buffer.WriteByte(':')
			if err := appendCanonicalJSON(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON type unsupported: %T", value)
	}
	return nil
}
