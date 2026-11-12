// Package proofstream implements the bounded, chained v3 upload profile.
// It performs no network calls and does not interpret application protobufs.
package proofstream

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/MotiveIQ/public/platform/iam/api/v1"
	"github.com/MotiveIQ/public/platform/iam/internal/proof"
)

const (
	Profile                       = "motiveiq-grpc-upload-v1"
	Transport     proof.Transport = "grpc-upload-v1"
	MaxPayload                    = 96 * 1024
	MaxBody                       = 128 * 1024
	MaxCredential                 = 16 * 1024
	MaxEnvelope                   = 192 * 1024
)

var ErrFrame = errors.New("invalid signed upload frame")

// Parse validates control framing before allocating protobuf fields. Application
// bytes remain opaque and retain ordinary protobuf evolution semantics.
func Parse(f *iamv1.SignedStreamFrame) (*iamv1.RequestStreamFrameBody, error) {
	if f == nil || len(f.Body) > MaxBody || len(f.Proof) == 0 || len(f.Proof) > MaxCredential || len(f.SessionToken) > MaxCredential || len(f.ProtoReflect().GetUnknown()) != 0 || proto.Size(f) > MaxEnvelope {
		return nil, ErrFrame
	}
	b := new(iamv1.RequestStreamFrameBody)
	if err := strict(f.Body, b.ProtoReflect().Descriptor()); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(f.Body, b); err != nil {
		return nil, ErrFrame
	}
	if b.Profile != Profile || len(b.StreamId) != 32 || len(b.PreviousFrameSha256) != 32 || b.Frame == nil {
		return nil, ErrFrame
	}
	switch v := b.Frame.(type) {
	case *iamv1.RequestStreamFrameBody_Open:
		if len(v.Open.RequestBytes) > MaxPayload || v.Open.DeadlineUnixSeconds <= 0 {
			return nil, ErrFrame
		}
	case *iamv1.RequestStreamFrameBody_Data:
		if len(v.Data) > MaxPayload {
			return nil, ErrFrame
		}
	}
	return b, nil
}

func strict(raw []byte, desc protoreflect.MessageDescriptor) error {
	seen := map[protowire.Number]bool{}
	oneofs := map[protoreflect.FullName]bool{}
	for len(raw) > 0 {
		n, typ, used := protowire.ConsumeTag(raw)
		if used < 0 || seen[n] {
			return ErrFrame
		}
		seen[n] = true
		field := desc.Fields().ByNumber(protoreflect.FieldNumber(n))
		if field == nil {
			return ErrFrame
		}
		if o := field.ContainingOneof(); o != nil {
			if oneofs[o.FullName()] {
				return ErrFrame
			}
			oneofs[o.FullName()] = true
		}
		raw = raw[used:]
		switch field.Kind() {
		case protoreflect.Uint64Kind, protoreflect.Int64Kind:
			if typ != protowire.VarintType {
				return ErrFrame
			}
			_, used = protowire.ConsumeVarint(raw)
		default:
			if typ != protowire.BytesType {
				return ErrFrame
			}
			var value []byte
			value, used = protowire.ConsumeBytes(raw)
			if used >= 0 && field.Kind() == protoreflect.MessageKind {
				if err := strict(value, field.Message()); err != nil {
					return err
				}
			}
		}
		if used < 0 {
			return ErrFrame
		}
		raw = raw[used:]
	}
	return nil
}

func FrameID(f *iamv1.SignedStreamFrame) [32]byte {
	h := sha256.New()
	h.Write([]byte("motiveiq-grpc-upload-frame-v1\x00"))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(f.Body)))
	h.Write(size[:])
	h.Write(f.Body)
	binary.BigEndian.PutUint32(size[:], uint32(len(f.Proof)))
	h.Write(size[:])
	h.Write([]byte(f.Proof))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func binding(base proof.Binding, token string, b *iamv1.RequestStreamFrameBody, raw []byte) proof.Binding {
	base.Version = proof.Version3
	base.Transport = Transport
	base.Method = "POST"
	base.RequestHash = proof.Digest(raw)
	base.BindToken = true
	base.TokenHash = proof.Digest([]byte(token))
	base.Nonce = base64.RawURLEncoding.EncodeToString(b.StreamId)
	return base
}

type state struct {
	id          []byte
	sequence    uint64
	previous    [32]byte
	count, size uint64
	finished    bool
}

func (s *state) accept(b *iamv1.RequestStreamFrameBody, f *iamv1.SignedStreamFrame) error {
	if s.finished || b.Sequence != s.sequence || b.Sequence == math.MaxUint64 || !bytes.Equal(b.StreamId, s.id) || !bytes.Equal(b.PreviousFrameSha256, s.previous[:]) {
		return ErrFrame
	}
	switch v := b.Frame.(type) {
	case *iamv1.RequestStreamFrameBody_Open:
		if s.sequence != 0 || f.SessionToken == "" {
			return ErrFrame
		}
	case *iamv1.RequestStreamFrameBody_Data:
		if s.sequence == 0 || f.SessionToken != "" || s.count == math.MaxUint64 || uint64(len(v.Data)) > math.MaxUint64-s.size {
			return ErrFrame
		}
		s.count++
		s.size += uint64(len(v.Data))
	case *iamv1.RequestStreamFrameBody_Finish:
		if s.sequence == 0 || f.SessionToken != "" || v.Finish.DataMessageCount != s.count || v.Finish.DataPayloadBytes != s.size {
			return ErrFrame
		}
		s.finished = true
	default:
		return ErrFrame
	}
	s.previous = FrameID(f)
	s.sequence++
	return nil
}

type Encoder struct {
	state
	signer   *proof.Signer
	token    string
	base     proof.Binding
	deadline time.Time
	now      func() time.Time
}

func NewEncoder(signer *proof.Signer, token string, base proof.Binding, deadline time.Time, now func() time.Time) (*Encoder, error) {
	if signer == nil || token == "" || len(token) > MaxCredential {
		return nil, ErrFrame
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &Encoder{state: state{id: id}, signer: signer, token: token, base: base, deadline: deadline.Truncate(time.Second), now: now}, nil
}
func (e *Encoder) Open(payload []byte) (*iamv1.SignedStreamFrame, error) {
	return e.sign(&iamv1.RequestStreamFrameBody{Frame: &iamv1.RequestStreamFrameBody_Open{Open: &iamv1.RequestStreamOpen{RequestBytes: payload, DeadlineUnixSeconds: e.deadline.Unix()}}})
}
func (e *Encoder) Data(payload []byte) (*iamv1.SignedStreamFrame, error) {
	return e.sign(&iamv1.RequestStreamFrameBody{Frame: &iamv1.RequestStreamFrameBody_Data{Data: payload}})
}
func (e *Encoder) Finish() (*iamv1.SignedStreamFrame, error) {
	return e.sign(&iamv1.RequestStreamFrameBody{Frame: &iamv1.RequestStreamFrameBody_Finish{Finish: &iamv1.RequestStreamFinish{DataMessageCount: e.count, DataPayloadBytes: e.size}}})
}
func (e *Encoder) sign(b *iamv1.RequestStreamFrameBody) (*iamv1.SignedStreamFrame, error) {
	b.Profile = Profile
	b.StreamId = e.id
	b.Sequence = e.sequence
	b.PreviousFrameSha256 = e.previous[:]
	raw, err := proto.Marshal(b)
	if err != nil {
		return nil, err
	}
	now := e.now()
	expiry := now.Truncate(time.Second).Add(proof.MaxLifetime)
	if e.deadline.Before(expiry) {
		expiry = e.deadline
	}
	if !now.Before(expiry) {
		return nil, ErrFrame
	}
	compact, err := e.signer.SignUntil(binding(e.base, e.token, b, raw), now, expiry)
	if err != nil {
		return nil, err
	}
	f := &iamv1.SignedStreamFrame{Body: raw, Proof: compact}
	if e.sequence == 0 {
		f.SessionToken = e.token
	}
	if _, err = Parse(f); err != nil {
		return nil, err
	}
	if err = e.accept(b, f); err != nil {
		return nil, err
	}
	return f, nil
}

type Decoder struct {
	state
	base              proof.Binding
	token, thumbprint string
	deadline          time.Time
	verifier          *proof.Verifier
	now               func() time.Time
}

// NewDecoder authenticates OPEN against independently verified session claims.
func NewDecoder(f *iamv1.SignedStreamFrame, base proof.Binding, thumbprint string, sessionExpiry time.Time, now func() time.Time) (*Decoder, *iamv1.RequestStreamOpen, proof.Verification, error) {
	var zero proof.Verification
	b, err := Parse(f)
	if err != nil || b.GetOpen() == nil || f.SessionToken == "" || thumbprint == "" {
		return nil, nil, zero, ErrFrame
	}
	deadline := time.Unix(b.GetOpen().DeadlineUnixSeconds, 0)
	if deadline.After(sessionExpiry) {
		deadline = sessionExpiry
	}
	if !now().Before(deadline) {
		return nil, nil, zero, ErrFrame
	}
	d := &Decoder{state: state{id: bytes.Clone(b.StreamId)}, base: base, token: f.SessionToken, thumbprint: thumbprint, deadline: deadline, verifier: proof.NewVerifier(now), now: now}
	v, err := d.verify(f, b)
	if err != nil {
		return nil, nil, zero, err
	}
	return d, b.GetOpen(), v, nil
}
func (d *Decoder) verify(f *iamv1.SignedStreamFrame, b *iamv1.RequestStreamFrameBody) (proof.Verification, error) {
	var zero proof.Verification
	if !d.now().Before(d.deadline) {
		return zero, ErrFrame
	}
	v, err := d.verifier.Verify(f.Proof, binding(d.base, d.token, b, f.Body))
	if err != nil || v.KeyThumbprint != d.thumbprint || v.ExpiresAt.After(d.deadline) {
		return zero, ErrFrame
	}
	if err = d.accept(b, f); err != nil {
		return zero, err
	}
	return v, nil
}

// Next returns authenticated DATA, or finished=true for a verified FIN. The
// transport must still require actual EOF before exposing successful completion.
func (d *Decoder) Next(f *iamv1.SignedStreamFrame) (payload []byte, finished bool, err error) {
	b, err := Parse(f)
	if err != nil {
		return nil, false, err
	}
	if _, err = d.verify(f, b); err != nil {
		return nil, false, err
	}
	return b.GetData(), d.finished, nil
}
