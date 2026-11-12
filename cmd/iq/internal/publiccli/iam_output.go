package publiccli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/jmespath/go-jmespath"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

// Output formats, mirroring the AWS CLI: json is the default, text is
// tab-separated with no headers, table is an aligned table with column
// headers.
const (
	outputJSON  = "json"
	outputYAML  = "yaml"
	outputText  = "text"
	outputTable = "table"
)

// iamTableCellWidth bounds table cells explicitly marked as large payloads.
// Policy documents and PEM bundles have no length worth fitting and would
// stretch a row past any terminal, so they are truncated to this fixed width
// — the last cell position spent on U+2026 — regardless of the terminal.
// Identifiers remain whole and copyable; json and text carry every value
// whole as well.
const (
	iamTableCellWidth = 72
	iamTableEllipsis  = "…"
)

const defaultOutputEnv = "IQ_DEFAULT_OUTPUT"

type iamOptions struct {
	Role string
	outputOptions
}

type outputOptions struct {
	Output string
	Query  string
	query  *jmespath.JMESPath
}

func (c *Command) addIAMFlags(command *cobra.Command, options *iamOptions) {
	flags := command.PersistentFlags()
	flags.StringVar(&options.Role, "role", options.Role, "IAM role URN to assume.")
	must(command.RegisterFlagCompletionFunc("role", cobra.NoFileCompletions))
	c.addOutputFlags(command, &options.outputOptions)
}

// Shared flags can appear before or after a subcommand, as in the AWS CLI.
func (c *Command) addOutputFlags(command *cobra.Command, options *outputOptions) {
	output := c.Env(defaultOutputEnv)
	if output == "" {
		output = outputJSON
	}
	command.PersistentFlags().StringVarP(&options.Output, "output", "o", output, "Output format: json, yaml, text or table (env: IQ_DEFAULT_OUTPUT).")
	must(command.RegisterFlagCompletionFunc("output", fixedCompletions(
		cobra.CompletionWithDesc(outputJSON, "machine-readable JSON (default)"),
		cobra.CompletionWithDesc(outputYAML, "machine-readable YAML"),
		cobra.CompletionWithDesc(outputText, "tab-separated values, no headers"),
		cobra.CompletionWithDesc(outputTable, "bordered table with column headers"),
	)))
	command.PersistentFlags().StringVar(&options.Query, "query", "", "JMESPath expression to filter the JSON response before formatting.")
	must(command.RegisterFlagCompletionFunc("query", cobra.NoFileCompletions))
}

func (options *outputOptions) validate() error {
	if err := validateIAMOutput(options.Output); err != nil {
		return err
	}
	options.query = nil
	if options.Query != "" {
		query, err := jmespath.Compile(options.Query)
		if err != nil {
			return fmt.Errorf("invalid --query: %w", err)
		}
		options.query = query
	}
	return nil
}

// iamView is the format-independent shape of one response: ordered field
// names plus a row of values per record. text and table both render from
// it, so which fields a command shows, and in what order, cannot drift
// between the two.
type iamView struct {
	fields []string
	rows   [][]string
	// tableCellWidths is aligned with fields. Zero preserves the value;
	// a positive value bounds that field in table output only.
	tableCellWidths []int
	// object marks a single record described field by field rather than a
	// list of records; table renders it as field/value pairs.
	object bool
}

// iamField is one field of a single-record response.
type iamField struct {
	name  string
	value string
}

func iamListView(fields []string, rows [][]string) iamView {
	return iamView{fields: fields, rows: rows}
}

func iamObjectView(fields []iamField, boundedTableFields ...string) iamView {
	bounded := make(map[string]struct{}, len(boundedTableFields))
	for _, field := range boundedTableFields {
		bounded[field] = struct{}{}
	}
	view := iamView{
		object:          true,
		fields:          make([]string, 0, len(fields)),
		tableCellWidths: make([]int, 0, len(fields)),
	}
	row := make([]string, 0, len(fields))
	for _, field := range fields {
		view.fields = append(view.fields, field.name)
		row = append(row, field.value)
		width := 0
		if _, ok := bounded[field.name]; ok {
			width = iamTableCellWidth
		}
		view.tableCellWidths = append(view.tableCellWidths, width)
	}
	view.rows = [][]string{row}
	return view
}

func (c *Command) printIAMResponse(options outputOptions, title string, message proto.Message, view func(proto.Message) iamView) error {
	payload, err := (protojson.MarshalOptions{EmitDefaultValues: true}).Marshal(message)
	if err != nil {
		return err
	}
	return c.printOutput(options, title, payload, func() iamView { return view(message) })
}

// Queries always see the complete JSON response, including fields omitted
// from the concise default tables. JSON field names and types stay unchanged.
func (c *Command) printOutput(options outputOptions, title string, payload []byte, view func() iamView) error {
	var result any
	if options.query != nil {
		if err := json.Unmarshal(payload, &result); err != nil {
			return err
		}
		var err error
		result, err = options.query.Search(result)
		if err != nil {
			return fmt.Errorf("evaluate --query: %w", err)
		}
		payload, err = json.Marshal(result)
		if err != nil {
			return err
		}
	}
	switch options.Output {
	case outputJSON:
		return writeIAMJSON(c.Stdout, payload)
	case outputYAML:
		// Decode JSON as a YAML node to retain integer precision and string
		// types (including protojson's quoted 64-bit integers).
		var node yaml.Node
		if err := yaml.Unmarshal(payload, &node); err != nil {
			return err
		}
		clearYAMLStyle(&node)
		encoder := yaml.NewEncoder(c.Stdout)
		encoder.SetIndent(2)
		if err := encoder.Encode(&node); err != nil {
			return err
		}
		return encoder.Close()
	default:
		var buffer bytes.Buffer
		if options.query == nil && view != nil {
			writeIAMView(&buffer, options.Output, title, view())
		} else {
			if options.query == nil {
				if err := json.Unmarshal(payload, &result); err != nil {
					return err
				}
			}
			if options.Output == outputText {
				writeIAMQueryText(&buffer, result, "")
			} else {
				writeIAMTable(&buffer, title, iamQueryView(result))
			}
		}
		_, err := buffer.WriteTo(c.Stdout)
		return err
	}
}

func clearYAMLStyle(node *yaml.Node) {
	node.Style = 0
	for _, child := range node.Content {
		clearYAMLStyle(child)
	}
}

// writeIAMJSON indents a marshalled response. protojson deliberately
// varies its own spacing between builds to discourage byte-for-byte
// dependence on it, which surfaces as a stray second space after a colon
// and as two builds of iq printing the same response differently.
// Re-indenting normalises that without touching field names, their order
// or their values, so a response renders the same bytes everywhere and
// stays diffable between runs, as the AWS CLI's does.
func writeIAMJSON(w io.Writer, payload []byte) error {
	indented := &bytes.Buffer{}
	if err := json.Indent(indented, payload, "", "    "); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, indented.String())
	return err
}

func writeIAMView(w io.Writer, output, title string, view iamView) {
	if output == outputTable {
		writeIAMTable(w, title, view)
		return
	}
	writeIAMText(w, view)
}

// writeIAMText renders AWS's text format: one record per line, values
// separated by tabs, no headers.
func writeIAMText(w io.Writer, view iamView) {
	for _, row := range view.rows {
		cells := make([]string, len(row))
		for i, value := range row {
			cells[i] = flattenIAMCell(value)
		}
		fmt.Fprintln(w, strings.Join(cells, "\t"))
	}
}

// writeIAMTable renders an ASCII frame with the action as its caption.
// Single objects use field/value rows to keep wide records readable.
// Empty result sets print nothing, as in the AWS CLI.
func writeIAMTable(w io.Writer, title string, view iamView) {
	headers, rows := view.fields, view.rows
	if view.object {
		headers, rows = []string{"field", "value"}, iamFieldRows(view)
	}
	if len(headers) == 0 || len(rows) == 0 {
		return
	}

	cells := make([][]string, 0, len(rows))
	for rowIndex, row := range rows {
		cell := make([]string, len(headers))
		for i := range cell {
			if i < len(row) {
				cell[i] = flattenIAMCell(row[i])
				if width := iamTableCellLimit(view, rowIndex, i); width > 0 {
					cell[i] = truncateIAMCell(cell[i], width)
				}
			}
		}
		cells = append(cells, cell)
	}

	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = iamCellWidth(header)
	}
	for _, row := range cells {
		for i, value := range row {
			widths[i] = max(widths[i], iamCellWidth(value))
		}
	}

	// Widen the last column when the caption would exceed the frame.
	width := iamTableRowWidth(widths)
	if extra := iamCellWidth(title) + 4 - width; extra > 0 {
		widths[len(widths)-1] += extra
		width += extra
	}
	frame := strings.Repeat("-", width)
	fmt.Fprintln(w, frame)
	padding := width - 2 - iamCellWidth(title)
	fmt.Fprintf(w, "|%s%s%s|\n", strings.Repeat(" ", padding/2), title, strings.Repeat(" ", padding-padding/2))
	fmt.Fprintln(w, frame)
	fmt.Fprintln(w, iamTableRow(headers, widths))
	separator := make([]string, len(widths))
	for i, width := range widths {
		separator[i] = strings.Repeat("-", width+2)
	}
	rule := "+" + strings.Join(separator, "+") + "+"
	fmt.Fprintln(w, rule)
	for _, row := range cells {
		fmt.Fprintln(w, iamTableRow(row, widths))
	}
	fmt.Fprintln(w, rule)
}

// iamTableCellLimit returns the opt-in width limit for one rendered cell.
// A list's fields are columns. An object is transposed into field/value rows,
// so each original field's limit applies only to the value in that row.
func iamTableCellLimit(view iamView, row, column int) int {
	field := column
	if view.object {
		if column != 1 {
			return 0
		}
		field = row
	}
	if field >= len(view.tableCellWidths) {
		return 0
	}
	return view.tableCellWidths[field]
}

func iamFieldRows(view iamView) [][]string {
	if len(view.rows) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(view.fields))
	for i, field := range view.fields {
		rows = append(rows, []string{field, view.rows[0][i]})
	}
	return rows
}

func iamTableRowWidth(widths []int) int {
	width := 1 + 3*len(widths)
	for _, column := range widths {
		width += column
	}
	return width
}

func iamTableRow(values []string, widths []int) string {
	cells := make([]string, 0, len(widths))
	for i, width := range widths {
		cells = append(cells, values[i]+strings.Repeat(" ", width-iamCellWidth(values[i])))
	}
	return "| " + strings.Join(cells, " | ") + " |"
}

// iamCellWidth is how many terminal columns a cell occupies. Counting
// runes is right for everything IAM stores — URNs, policy documents, PEM
// bundles, RFC 3339 timestamps are all ASCII — but a double-width CJK
// character or an emoji in, say, a session name would count one and
// occupy two, indenting the rest of that row by one. Fixing that needs a
// rune-width table; no such package is in the module graph, and a new
// dependency costs more here than the misalignment it would prevent.
func iamCellWidth(value string) int {
	return utf8.RuneCountInString(value)
}

var iamCellFlattener = strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")

// flattenIAMCell keeps a value on one line: PEM bundles and policy
// documents carry newlines, and text separates values with tabs, so either
// character would break the record shape. Trailing whitespace goes too — a
// bundle's final newline would otherwise pad the record's last value.
func flattenIAMCell(value string) string {
	return strings.TrimSpace(iamCellFlattener.Replace(value))
}

func truncateIAMCell(value string, maxWidth int) string {
	if iamCellWidth(value) <= maxWidth {
		return value
	}
	return string([]rune(value)[:maxWidth-1]) + iamTableEllipsis
}

func validateIAMOutput(output string) error {
	switch output {
	case outputJSON, outputYAML, outputText, outputTable:
		return nil
	}
	return fmt.Errorf("%q is not a valid output format; expected one of: json, yaml, text, table", output)
}

func iamActionError(err error, action string) error {
	if status.Code(err) == codes.PermissionDenied {
		return fmt.Errorf("%s (requires %s)", status.Convert(err).Message(), action)
	}
	return err
}

func formatIAMTime(value *timestamppb.Timestamp) string {
	if value == nil {
		return "unknown"
	}
	return value.AsTime().UTC().Format("2006-01-02T15:04:05+00:00")
}
