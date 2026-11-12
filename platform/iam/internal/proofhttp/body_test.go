package proofhttp_test

import (
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"

	"go.motiveiq.dev/platform/iam/internal/proofhttp"
)

type trackingBody struct {
	reader   io.Reader
	reads    int
	closed   bool
	closeErr error
}

func (b *trackingBody) Read(p []byte) (int, error) {
	b.reads++
	return b.reader.Read(p)
}

func (b *trackingBody) Close() error {
	b.closed = true
	return b.closeErr
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestReadAndRestoreBody(t *testing.T) {
	t.Parallel()
	original := &trackingBody{reader: strings.NewReader("exact bytes")}
	req := &http.Request{Body: original, ContentLength: -1}
	body, err := proofhttp.ReadAndRestoreBody(req, int64(len("exact bytes")))
	if err != nil {
		t.Fatalf("ReadAndRestoreBody: %v", err)
	}
	if !original.closed {
		t.Error("original body was not closed")
	}
	if string(body) != "exact bytes" {
		t.Fatalf("body = %q", body)
	}

	// The returned bytes do not alias the body installed on the request.
	body[0] = 'X'
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(restored) != "exact bytes" {
		t.Errorf("restored body = %q, want exact bytes", restored)
	}
	if req.GetBody == nil {
		t.Fatal("GetBody was not installed")
	}
	retryBody, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody: %v", err)
	}
	retry, err := io.ReadAll(retryBody)
	if err != nil {
		t.Fatalf("read retry body: %v", err)
	}
	_ = retryBody.Close()
	if string(retry) != "exact bytes" {
		t.Errorf("retry body = %q, want exact bytes", retry)
	}
}

func TestReadAndRestoreBodyLimits(t *testing.T) {
	t.Parallel()
	t.Run("unknown length exceeds limit", func(t *testing.T) {
		original := &trackingBody{reader: strings.NewReader("12345")}
		req := &http.Request{Body: original, ContentLength: -1}
		_, err := proofhttp.ReadAndRestoreBody(req, 4)
		if !errors.Is(err, proofhttp.ErrBodyTooLarge) {
			t.Fatalf("error = %v, want ErrBodyTooLarge", err)
		}
		if !original.closed || req.Body != http.NoBody || req.GetBody != nil {
			t.Errorf("failed request was not closed and disabled: closed=%v body=%T getBody=%v",
				original.closed, req.Body, req.GetBody != nil)
		}
	})

	t.Run("declared length exceeds limit", func(t *testing.T) {
		original := &trackingBody{reader: strings.NewReader("1")}
		req := &http.Request{Body: original, ContentLength: 100}
		_, err := proofhttp.ReadAndRestoreBody(req, 4)
		if !errors.Is(err, proofhttp.ErrBodyTooLarge) {
			t.Fatalf("error = %v, want ErrBodyTooLarge", err)
		}
		if !original.closed {
			t.Error("declared-oversize body was not closed")
		}
	})

	t.Run("zero permits empty body", func(t *testing.T) {
		req := &http.Request{Body: http.NoBody}
		body, err := proofhttp.ReadAndRestoreBody(req, 0)
		if err != nil {
			t.Fatalf("empty body: %v", err)
		}
		if len(body) != 0 {
			t.Errorf("empty body length = %d", len(body))
		}
	})

	t.Run("zero rejects nonempty body", func(t *testing.T) {
		req := &http.Request{Body: io.NopCloser(strings.NewReader("x")), ContentLength: -1}
		if _, err := proofhttp.ReadAndRestoreBody(req, 0); !errors.Is(err, proofhttp.ErrBodyTooLarge) {
			t.Errorf("error = %v, want ErrBodyTooLarge", err)
		}
	})

	for _, limit := range []int64{-1, math.MaxInt64} {
		t.Run("invalid limit", func(t *testing.T) {
			req := &http.Request{Body: http.NoBody}
			if _, err := proofhttp.ReadAndRestoreBody(req, limit); !errors.Is(err, proofhttp.ErrInvalidBodyLimit) {
				t.Errorf("limit %d error = %v, want ErrInvalidBodyLimit", limit, err)
			}
		})
	}
}

func TestReadAndRestoreBodyIOFailures(t *testing.T) {
	t.Parallel()
	t.Run("read", func(t *testing.T) {
		original := &trackingBody{reader: failingReader{}}
		req := &http.Request{Body: original, ContentLength: -1}
		_, err := proofhttp.ReadAndRestoreBody(req, 16)
		if !errors.Is(err, proofhttp.ErrReadBody) {
			t.Fatalf("error = %v, want ErrReadBody", err)
		}
		if !original.closed || req.Body != http.NoBody {
			t.Error("read-failed body was not closed and disabled")
		}
	})

	t.Run("close", func(t *testing.T) {
		original := &trackingBody{reader: strings.NewReader("ok"), closeErr: errors.New("close failed")}
		req := &http.Request{Body: original, ContentLength: -1}
		_, err := proofhttp.ReadAndRestoreBody(req, 16)
		if !errors.Is(err, proofhttp.ErrReadBody) {
			t.Fatalf("error = %v, want ErrReadBody", err)
		}
		if !original.closed || req.Body != http.NoBody {
			t.Error("close-failed body was not disabled")
		}
	})
}

func TestNewRejectsInvalidBodyLimit(t *testing.T) {
	t.Parallel()
	for _, limit := range []int64{-1, math.MaxInt64} {
		_, err := proofhttp.New(proofhttp.Config{
			Origin:       "https://api.example.com",
			MaxBodyBytes: limit,
		})
		if !errors.Is(err, proofhttp.ErrInvalidBodyLimit) {
			t.Errorf("limit %d error = %v, want ErrInvalidBodyLimit", limit, err)
		}
	}
}
