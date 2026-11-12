package proofstream

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	iamv1 "github.com/MotiveIQ/public/platform/iam/api/v1"
	"github.com/MotiveIQ/public/platform/iam/internal/proof"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func fixture(t testing.TB) (*Encoder, func(*iamv1.SignedStreamFrame) (*Decoder, error), *time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	signer, err := proof.GenerateSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := proof.Binding{Operation: "/test.Service/Upload", TargetURI: "https://example.com/test.Service/Upload", Metadata: map[string]string{"x-tenant": "one"}}
	clock := func() time.Time { return now }
	expiry := now.Add(time.Hour)
	e, err := NewEncoder(signer, "session", base, expiry, clock)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(f *iamv1.SignedStreamFrame) (*Decoder, error) {
		d, _, _, err := NewDecoder(f, base, signer.Thumbprint(), expiry, clock)
		return d, err
	}
	return e, decode, &now
}
func open(t testing.TB, e *Encoder) *iamv1.SignedStreamFrame {
	t.Helper()
	f, err := e.Open([]byte("header"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func data(t testing.TB, e *Encoder, p []byte) *iamv1.SignedStreamFrame {
	t.Helper()
	f, err := e.Data(p)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func finish(t testing.TB, e *Encoder) *iamv1.SignedStreamFrame {
	t.Helper()
	f, err := e.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func TestFreshFramesOutliveOpenProof(t *testing.T) {
	e, decode, now := fixture(t)
	d, err := decode(open(t, e))
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	payload, done, err := d.Next(data(t, e, []byte("object")))
	if err != nil || done || string(payload) != "object" {
		t.Fatalf("DATA: %q %v %v", payload, done, err)
	}
	if _, done, err = d.Next(finish(t, e)); err != nil || !done {
		t.Fatalf("FIN: %v %v", done, err)
	}
	if _, _, err = d.Next(&iamv1.SignedStreamFrame{Proof: "irrelevant"}); err == nil {
		t.Fatal("accepted a frame after FIN")
	}
}
func TestEmptyUpload(t *testing.T) {
	e, decode, _ := fixture(t)
	d, err := decode(open(t, e))
	if err != nil {
		t.Fatal(err)
	}
	if _, done, err := d.Next(finish(t, e)); err != nil || !done {
		t.Fatal(done, err)
	}
}
func TestTamperingAndOrdering(t *testing.T) {
	for _, name := range []string{"equal-length-data", "proof", "token", "sequence", "parent", "stream-id", "profile", "repeat", "gap", "splice", "expired", "counts"} {
		t.Run(name, func(t *testing.T) {
			e, decode, now := fixture(t)
			o := open(t, e)
			d, err := decode(o)
			if err != nil {
				t.Fatal(err)
			}
			first := data(t, e, []byte("original"))
			second := data(t, e, []byte("second"))
			f := proto.Clone(first).(*iamv1.SignedStreamFrame)
			b := new(iamv1.RequestStreamFrameBody)
			if err := proto.Unmarshal(f.Body, b); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "equal-length-data":
				b.Frame = &iamv1.RequestStreamFrameBody_Data{Data: []byte("modified")}
			case "sequence":
				b.Sequence++
			case "parent":
				b.PreviousFrameSha256[0] ^= 1
			case "stream-id":
				b.StreamId[0] ^= 1
			case "profile":
				b.Profile = "other"
			case "proof":
				f.Proof = f.Proof[:len(f.Proof)-1] + "!"
			case "token":
				f.SessionToken = "injected"
			case "repeat":
				if _, _, err = d.Next(first); err != nil {
					t.Fatal(err)
				}
			case "gap":
				f = second
			case "splice":
				other, _, _ := fixture(t)
				open(t, other)
				f = data(t, other, []byte("original"))
			case "expired":
				*now = now.Add(31 * time.Second)
			case "counts":
				// Correctly signed FIN with totals inconsistent with what the decoder saw.
				e.count = 0
				e.size = 0
				f = finish(t, e)
				if _, _, err = d.Next(first); err != nil {
					t.Fatal(err)
				}
				if _, _, err = d.Next(second); err != nil {
					t.Fatal(err)
				}
			}
			if name == "equal-length-data" || name == "sequence" || name == "parent" || name == "stream-id" || name == "profile" {
				f.Body, err = proto.Marshal(b)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err = d.Next(f); err == nil {
				t.Fatal("accepted tampered frame")
			}
		})
	}
}
func TestBindingAndLimits(t *testing.T) {
	for _, name := range []string{"origin", "method", "metadata", "key", "token", "body-limit", "payload-limit", "unknown-envelope"} {
		t.Run(name, func(t *testing.T) {
			e, decode, _ := fixture(t)
			f := open(t, e)
			switch name {
			case "origin":
				e.base.TargetURI = "https://other.example/test.Service/Upload"
			case "method":
				e.base.Operation = "/test.Service/Other"
			case "metadata":
				e.base.Metadata = map[string]string{"x-tenant": "two"}
			case "key":
				e.signer, _ = proof.GenerateSigner(nil)
			case "token":
				f.SessionToken = "other"
			case "body-limit":
				f.Body = make([]byte, MaxBody+1)
			case "payload-limit":
				_, err := e.Data(make([]byte, MaxPayload+1))
				if err == nil {
					t.Fatal("accepted oversized payload")
				}
				return
			case "unknown-envelope":
				f.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1))
			}
			if name == "origin" || name == "method" || name == "metadata" || name == "key" {
				d, err := decode(f)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err = d.Next(data(t, e, []byte("data"))); err == nil {
					t.Fatal("accepted wrong binding")
				}
				return
			}
			if _, err := decode(f); err == nil {
				t.Fatal("accepted invalid OPEN")
			}
		})
	}
}
func TestStrictControlParsing(t *testing.T) {
	for _, name := range []string{"duplicate-sequence", "unknown", "wrong-wire", "second-oneof", "duplicate-nested", "missing-kind"} {
		t.Run(name, func(t *testing.T) {
			e, _, _ := fixture(t)
			f := open(t, e)
			switch name {
			case "duplicate-sequence":
				f.Body = protowire.AppendVarint(protowire.AppendTag(f.Body, 3, protowire.VarintType), 0)
				f.Body = protowire.AppendVarint(protowire.AppendTag(f.Body, 3, protowire.VarintType), 0)
			case "unknown":
				f.Body = protowire.AppendBytes(protowire.AppendTag(f.Body, 99, protowire.BytesType), nil)
			case "wrong-wire":
				f.Body = protowire.AppendBytes(protowire.AppendTag(f.Body, 3, protowire.BytesType), nil)
			case "second-oneof":
				f.Body = protowire.AppendBytes(protowire.AppendTag(f.Body, 6, protowire.BytesType), nil)
			case "duplicate-nested":
				b := new(iamv1.RequestStreamFrameBody)
				proto.Unmarshal(f.Body, b)
				b.Frame = nil
				f.Body, _ = proto.Marshal(b)
				nested := protowire.AppendVarint(protowire.AppendTag(nil, 2, protowire.VarintType), 1)
				nested = append(nested, nested...)
				f.Body = protowire.AppendBytes(protowire.AppendTag(f.Body, 5, protowire.BytesType), nested)
			case "missing-kind":
				b := new(iamv1.RequestStreamFrameBody)
				proto.Unmarshal(f.Body, b)
				b.Frame = nil
				f.Body, _ = proto.Marshal(b)
			}
			if _, err := Parse(f); err == nil {
				t.Fatal("accepted ambiguous control encoding")
			}
		})
	}
}
func TestFrameIDVector(t *testing.T) {
	got := FrameID(&iamv1.SignedStreamFrame{Body: []byte("body"), Proof: "proof"})
	const expected = "44223aa54e2a70b467f796f5ee1b7a37b3c499715ccde513947c56d2fb5fbd97"
	if hex.EncodeToString(got[:]) != expected {
		t.Fatalf("frame id %x", got)
	}
}
func FuzzParse(f *testing.F) {
	e, _, _ := fixture(f)
	f.Add(open(f, e).Body)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > MaxBody+1 {
			t.Skip()
		}
		_, _ = Parse(&iamv1.SignedStreamFrame{Body: body, Proof: "x"})
	})
}
func BenchmarkSignedFrames(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		e, decode, _ := fixture(b)
		d, err := decode(open(b, e))
		if err != nil {
			b.Fatal(err)
		}
		payload := bytes.Repeat([]byte("x"), 64*1024)
		for pb.Next() {
			frame := data(b, e, payload)
			if _, _, err := d.Next(frame); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.SetBytes(64 * 1024)
	b.ReportAllocs()
}

func TestCountersCannotWrap(t *testing.T) {
	for _, counter := range []string{"sequence", "messages", "bytes"} {
		t.Run(counter, func(t *testing.T) {
			e, _, _ := fixture(t)
			open(t, e)
			switch counter {
			case "sequence":
				e.sequence = ^uint64(0)
			case "messages":
				e.count = ^uint64(0)
			case "bytes":
				e.size = ^uint64(0)
			}
			if _, err := e.Data([]byte("x")); err == nil {
				t.Fatal("counter wrapped")
			}
		})
	}
}
func TestSessionExpiryCapsStreamAndProof(t *testing.T) {
	e, decode, now := fixture(t)
	e.deadline = now.Add(2 * time.Second)
	d, err := decode(open(t, e))
	if err != nil {
		t.Fatal(err)
	}
	frame := data(t, e, []byte("x"))
	*now = now.Add(3 * time.Second)
	if _, _, err = d.Next(frame); err == nil {
		t.Fatal("accepted data after deadline")
	}
	if _, err = e.Finish(); err == nil {
		t.Fatal("signed FIN after deadline")
	}
}
