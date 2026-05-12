package docker

import (
	"bytes"
	"encoding/binary"
	"io"
)

// dockerStreamHeaderLen is the length of the demultiplexing header Docker
// prefixes to each frame when the container has no TTY.
const dockerStreamHeaderLen = 8

// stripDockerStreamHeader returns an io.Reader that drops Docker's 8-byte
// per-frame header. When a container runs without a TTY the log stream is
// multiplexed and prefixed with [STREAM_TYPE, 0, 0, 0, SIZE_BE32]; with a TTY
// the stream is raw text. We detect the header heuristically and pass through
// raw text unchanged.
func stripDockerStreamHeader(r io.Reader) io.Reader {
	return &streamReader{src: r}
}

type streamReader struct {
	src       io.Reader
	frameLeft int
	rawMode   bool
	probed    bool
	probeBuf  []byte
}

func (s *streamReader) Read(p []byte) (int, error) {
	if !s.probed {
		// Peek the first header — if STREAM_TYPE is 0/1/2 and bytes [1:4] are
		// zero, assume multiplexed. Otherwise raw.
		hdr := make([]byte, dockerStreamHeaderLen)
		n, err := io.ReadFull(s.src, hdr)
		s.probed = true
		if err != nil && err != io.ErrUnexpectedEOF {
			return 0, err
		}
		if n < dockerStreamHeaderLen {
			s.rawMode = true
			s.probeBuf = hdr[:n]
		} else if hdr[0] <= 2 && hdr[1] == 0 && hdr[2] == 0 && hdr[3] == 0 {
			s.frameLeft = int(binary.BigEndian.Uint32(hdr[4:]))
		} else {
			s.rawMode = true
			s.probeBuf = bytes.Clone(hdr)
		}
	}
	if s.rawMode {
		if len(s.probeBuf) > 0 {
			n := copy(p, s.probeBuf)
			s.probeBuf = s.probeBuf[n:]
			return n, nil
		}
		return s.src.Read(p)
	}
	for s.frameLeft == 0 {
		var hdr [dockerStreamHeaderLen]byte
		if _, err := io.ReadFull(s.src, hdr[:]); err != nil {
			return 0, err
		}
		if hdr[0] > 2 || hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 {
			// Bad framing — switch to raw mode and replay what we have.
			s.rawMode = true
			s.probeBuf = bytes.Clone(hdr[:])
			n := copy(p, s.probeBuf)
			s.probeBuf = s.probeBuf[n:]
			return n, nil
		}
		s.frameLeft = int(binary.BigEndian.Uint32(hdr[4:]))
	}
	max := len(p)
	if max > s.frameLeft {
		max = s.frameLeft
	}
	n, err := s.src.Read(p[:max])
	s.frameLeft -= n
	return n, err
}
