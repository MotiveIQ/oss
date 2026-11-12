package transport

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
)

// HeaderValues deliberately does not use http.Header.Values: Values
// canonicalizes the lookup key and can miss a second entry inserted directly
// under a lowercase or otherwise noncanonical map key.
func HeaderValues(header http.Header, name string) []string {
	var values []string
	for key, current := range header {
		if strings.EqualFold(key, name) {
			values = append(values, current...)
		}
	}
	return values
}

func ValidateHTTPMetadata(names []string) error {
	return proof.ValidateApplicationMetadataNames(proof.TransportHTTP, names)
}

func SignedHTTPMetadata(header http.Header, names []string) (map[string]string, error) {
	fields := make(map[string]string, len(names))
	for _, name := range names {
		values := HeaderValues(header, name)
		if len(values) != 1 {
			return nil, fmt.Errorf("motiveiq: signed header %q requires exactly one value", name)
		}
		fields[name] = values[0]
	}
	if err := proof.ValidateMetadata(fields); err != nil {
		return nil, err
	}
	return fields, nil
}

func EscapedPathOperation(req *http.Request) (string, error) {
	if req == nil || req.URL == nil {
		return "", errors.New("nil request URL")
	}
	operation := req.URL.EscapedPath()
	if operation == "" {
		operation = "/"
	}
	return operation, nil
}
