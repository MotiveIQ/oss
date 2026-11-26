package publiccli

import (
	"go.motiveiq.dev/lib/resourceurn"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	kmsKeyPrefix   = "urn:iq:kms:key/"
	kmsAliasPrefix = "urn:iq:kms:alias/"
)

var kmsAliasPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
var kmsContextKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func kmsKey(value string, allowAlias bool) (string, error) {
	value = resourceurn.Current(value)
	if allowAlias && (strings.HasPrefix(value, "alias/") || strings.HasPrefix(value, kmsAliasPrefix)) {
		return kmsAlias(value)
	}
	id := strings.TrimPrefix(value, kmsKeyPrefix)
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return "", fmt.Errorf("key must be a lowercase UUID or canonical MotiveIQ key URN")
	}
	return kmsKeyPrefix + id, nil
}

func kmsAlias(value string) (string, error) {
	value = resourceurn.Current(value)
	var path string
	switch {
	case strings.HasPrefix(value, kmsAliasPrefix):
		path = strings.TrimPrefix(value, kmsAliasPrefix)
	case strings.HasPrefix(value, "alias/"):
		path = strings.TrimPrefix(value, "alias/")
	default:
		return "", fmt.Errorf("alias must start with alias/ or %s", kmsAliasPrefix)
	}
	parts := strings.Split(path, "/")
	if len(parts) > 8 {
		return "", fmt.Errorf("alias must contain at most eight path segments")
	}
	for _, part := range parts {
		if !kmsAliasPart.MatchString(part) {
			return "", fmt.Errorf("invalid alias path segment")
		}
	}
	return kmsAliasPrefix + path, nil
}

// Bound file reads as well as decoded inputs. Errors never include input contents.
func kmsInput(value, flag string, limit int) ([]byte, error) {
	prefix := ""
	if strings.HasPrefix(value, "fileb://") {
		prefix = "fileb://"
	} else if strings.HasPrefix(value, "file://") {
		prefix = "file://"
	}
	if prefix == "" {
		if len(value) > limit {
			return nil, fmt.Errorf("--%s input is too large", flag)
		}
		return []byte(value), nil
	}
	file, err := os.Open(strings.TrimPrefix(value, prefix))
	if err != nil {
		return nil, fmt.Errorf("read --%s file: %w", flag, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read --%s file: %w", flag, err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("--%s file is too large", flag)
	}
	return data, nil
}

func kmsBlob(value, flag, format string, limit int) ([]byte, error) {
	data, err := kmsInput(value, flag, 2*limit+1024)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(value, "fileb://") && format == "base64" {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, decodeErr := base64.StdEncoding.Decode(decoded, data)
		clear(data)
		if decodeErr != nil {
			clear(decoded)
			return nil, fmt.Errorf("--%s must be base64; use fileb:// for raw bytes", flag)
		}
		data = decoded[:n]
	}
	if len(data) == 0 || len(data) > limit {
		clear(data)
		return nil, fmt.Errorf("--%s must decode to 1–%d bytes", flag, limit)
	}
	return data, nil
}

func kmsText(value, flag string, limit int) (string, error) {
	if strings.HasPrefix(value, "fileb://") {
		return "", fmt.Errorf("--%s is text; use file://", flag)
	}
	data, err := kmsInput(value, flag, limit)
	if err != nil {
		return "", err
	}
	defer clear(data)
	if !utf8.Valid(data) {
		return "", fmt.Errorf("--%s must be UTF-8 text", flag)
	}
	return string(data), nil
}

func kmsContext(value, flag string) (map[string]string, error) {
	if value == "" {
		return nil, nil
	}
	raw, err := kmsText(value, flag, 16*1024)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	invalid := func() (map[string]string, error) {
		return nil, fmt.Errorf("--%s requires a JSON string map or key=value,key=value (quote or escape commas)", flag)
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		decoder := json.NewDecoder(strings.NewReader(raw))
		if _, err := decoder.Token(); err != nil {
			return invalid()
		}
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok {
				return invalid()
			}
			token, err = decoder.Token()
			val, ok := token.(string)
			if err != nil || !ok {
				return invalid()
			}
			if _, exists := out[key]; exists {
				return invalid()
			}
			out[key] = val
		}
		if _, err := decoder.Token(); err != nil {
			return invalid()
		}
		if _, err := decoder.Token(); err != io.EOF {
			return invalid()
		}
	} else {
		// A small string-map shorthand parser: quotes and backslash escapes protect
		// commas/equals. Unlike strings.Split, it preserves context values exactly.
		for rest := raw; rest != ""; {
			key, tail, err := kmsShorthandPart(rest, '=')
			if err != nil || tail == "" {
				return invalid()
			}
			val, next, err := kmsShorthandPart(tail[1:], ',')
			if err != nil {
				return invalid()
			}
			if _, exists := out[key]; exists {
				return invalid()
			}
			out[key] = val
			rest = next
			if rest != "" {
				rest = rest[1:]
				if strings.TrimSpace(rest) == "" {
					return invalid()
				}
			}
		}
	}
	size := 2
	for key, value := range out {
		if !kmsContextKey.MatchString(key) || !utf8.ValidString(value) {
			return nil, fmt.Errorf("invalid --%s key or UTF-8 value", flag)
		}
		size += 4 + len(key) + len(value)
	}
	if len(out) > 16 || size > 2048 {
		return nil, fmt.Errorf("--%s exceeds KMS limits (16 entries, 2048 encoded bytes)", flag)
	}
	return out, nil
}

func kmsShorthandPart(input string, delimiter byte) (string, string, error) {
	var out strings.Builder
	var quote byte
	// Trim only unquoted exterior whitespace; spaces within quoted values survive.
	input = strings.TrimLeft(input, " \t\r\n")
	keep := 0
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if ch == '\\' {
			i++
			if i == len(input) {
				return "", "", fmt.Errorf("unfinished escape")
			}
			out.WriteByte(input[i])
			keep = out.Len()
		} else if quote != 0 {
			if ch == quote {
				quote = 0
			} else {
				out.WriteByte(ch)
				keep = out.Len()
			}
		} else if ch == '\'' || ch == '"' {
			quote = ch
		} else if ch == delimiter {
			return out.String()[:keep], input[i:], nil
		} else {
			out.WriteByte(ch)
			if !strings.ContainsRune(" \t\r\n", rune(ch)) {
				keep = out.Len()
			}
		}
	}
	if quote != 0 {
		return "", "", fmt.Errorf("unfinished quote")
	}
	return out.String()[:keep], "", nil
}
