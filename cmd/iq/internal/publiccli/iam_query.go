package publiccli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// AWS text output sorts object keys, labels nested records, and preserves
// the column order of explicit lists such as roles[].[name, urn].
func writeIAMQueryText(w io.Writer, value any, label string) {
	switch value := value.(type) {
	case map[string]any:
		keys := iamQueryKeys(value)
		var scalars []string
		for _, key := range keys {
			if !iamQueryComposite(value[key]) {
				scalars = append(scalars, iamQueryScalar(value[key]))
			}
		}
		if len(scalars) > 0 {
			writeIAMQueryTextRow(w, scalars, label)
		}
		for _, key := range keys {
			if iamQueryComposite(value[key]) {
				writeIAMQueryText(w, value[key], key)
			}
		}
	case []any:
		var scalars []string
		for _, item := range value {
			if !iamQueryComposite(item) {
				scalars = append(scalars, iamQueryScalar(item))
			}
		}
		if len(scalars) > 0 {
			writeIAMQueryTextRow(w, scalars, label)
		}
		for _, item := range value {
			if iamQueryComposite(item) {
				writeIAMQueryText(w, item, label)
			}
		}
	default:
		writeIAMQueryTextRow(w, []string{iamQueryScalar(value)}, label)
	}
}

func writeIAMQueryTextRow(w io.Writer, cells []string, label string) {
	if label != "" {
		cells = append([]string{strings.ToUpper(label)}, cells...)
	}
	fmt.Fprintln(w, strings.Join(cells, "\t"))
}

func iamQueryComposite(value any) bool {
	switch value.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func iamQueryKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func iamQueryScalar(value any) string {
	switch value := value.(type) {
	case nil:
		return "None"
	case string:
		return value
	case bool:
		if value {
			return "True"
		}
		return "False"
	case float64:
		return strconv.FormatFloat(value, 'g', -1, 64)
	default:
		// Nested table cells retain their structure as compact JSON.
		payload, _ := json.Marshal(value)
		return string(payload)
	}
}

// Tables accept scalar, object, scalar-list, list-of-lists and object-list
// query results. Objects use alphabetic columns; explicit lists retain order.
// Composite cells are JSON so queries never silently discard nested data.
func iamQueryView(value any) iamView {
	switch value := value.(type) {
	case map[string]any:
		fields := make([]iamField, 0, len(value))
		for _, key := range iamQueryKeys(value) {
			fields = append(fields, iamField{key, iamQueryScalar(value[key])})
		}
		return iamObjectView(fields)
	case []any:
		if len(value) == 0 {
			return iamView{}
		}
		keys := map[string]any{}
		allObjects := true
		for _, item := range value {
			object, ok := item.(map[string]any)
			if !ok {
				allObjects = false
				break
			}
			for key := range object {
				keys[key] = nil
			}
		}
		if allObjects {
			fields := iamQueryKeys(keys)
			rows := make([][]string, 0, len(value))
			for _, item := range value {
				object := item.(map[string]any)
				row := make([]string, len(fields))
				for i, field := range fields {
					row[i] = iamQueryScalar(object[field])
				}
				rows = append(rows, row)
			}
			return iamListView(fields, rows)
		}
		width := 1
		rows := make([][]string, 0, len(value))
		for _, item := range value {
			items, ok := item.([]any)
			if !ok {
				items = []any{item}
			}
			row := make([]string, len(items))
			for i, cell := range items {
				row[i] = iamQueryScalar(cell)
			}
			width = max(width, len(row))
			rows = append(rows, row)
		}
		fields := []string{"value"}
		if width > 1 {
			fields = make([]string, width)
			for i := range fields {
				fields[i] = strconv.Itoa(i + 1)
			}
		}
		return iamListView(fields, rows)
	default:
		return iamListView([]string{"value"}, [][]string{{iamQueryScalar(value)}})
	}
}
