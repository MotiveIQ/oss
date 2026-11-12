package proofhttp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
)

var (
	// ErrBodyTooLarge reports a request body larger than its configured
	// authenticated-body bound.
	ErrBodyTooLarge = errors.New("proofhttp: request body exceeds limit")
	// ErrReadBody reports an I/O or close failure while capturing a request
	// body for authentication.
	ErrReadBody = errors.New("proofhttp: read request body")
)

// ReadAndRestoreBody reads at most maxBytes from req.Body and installs a fresh
// reader over the exact bytes on success. It also installs GetBody so a future
// client retry can obtain the same bytes and create a fresh proof. The returned
// slice does not alias the restored body.
//
// On failure, the original body is closed and replaced with http.NoBody. A
// caller must reject the request rather than invoking a handler or transport.
func ReadAndRestoreBody(req *http.Request, maxBytes int64) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil HTTP request", ErrInvalidRequest)
	}
	if maxBytes < 0 || maxBytes == math.MaxInt64 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidBodyLimit, maxBytes)
	}
	if req.Body == nil || req.Body == http.NoBody {
		if req.ContentLength > maxBytes {
			return nil, fmt.Errorf("%w: declared %d bytes, limit %d", ErrBodyTooLarge, req.ContentLength, maxBytes)
		}
		return []byte{}, nil
	}

	original := req.Body
	fail := func(err error) ([]byte, error) {
		_ = original.Close()
		req.Body = http.NoBody
		req.GetBody = nil
		return nil, err
	}
	if req.ContentLength > maxBytes {
		return fail(fmt.Errorf("%w: declared %d bytes, limit %d", ErrBodyTooLarge, req.ContentLength, maxBytes))
	}

	body, err := io.ReadAll(io.LimitReader(original, maxBytes+1))
	if err != nil {
		return fail(fmt.Errorf("%w: %v", ErrReadBody, err))
	}
	if int64(len(body)) > maxBytes {
		return fail(fmt.Errorf("%w: limit %d", ErrBodyTooLarge, maxBytes))
	}
	if err := original.Close(); err != nil {
		req.Body = http.NoBody
		req.GetBody = nil
		return nil, fmt.Errorf("%w: close: %v", ErrReadBody, err)
	}

	snapshot := append([]byte(nil), body...)
	req.Body = io.NopCloser(bytes.NewReader(snapshot))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(snapshot)), nil
	}
	return append([]byte(nil), snapshot...), nil
}
