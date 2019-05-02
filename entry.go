package esni

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/pkg/errors"
)

// KeyShareEntry represents a public key
// of a specific type presented as supported
// by the server for the purpose of encrypting
// an SNI
type KeyShareEntry struct {
	// Group specifies the encryption type
	// of the public key
	Group Group

	// KeyExchange represents the bytes of
	// the public key
	KeyExchange []byte
}

// Size returns the number of bytes that the
// entry would produce when marshaled to a binary
// format
func (entry KeyShareEntry) Size() uint16 {
	return uint16(len(entry.KeyExchange)) + 4
}

// MarshalBinary will marshal the entry into
// a binary format to be included in a list of
// supported keys
func (entry KeyShareEntry) MarshalBinary() ([]byte, error) {
	data := make([]byte, entry.Size())

	binary.BigEndian.PutUint16(data[0:2], uint16(entry.Group))
	binary.BigEndian.PutUint16(data[2:4], uint16(len(entry.KeyExchange)))
	copy(data[4:], entry.KeyExchange)

	return data, nil
}

// UnmarshalBinary will attempt to unmarshal
// a key share entry from the provided binary
// data
func (entry *KeyShareEntry) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.Wrap(io.ErrUnexpectedEOF, "buffer is too small for key share entry")
	}

	entry.Group = Group(binary.BigEndian.Uint16(data[:2]))

	keyLen := binary.BigEndian.Uint16(data[2:])
	if len(data) < int(keyLen)+4 {
		return errors.Wrap(io.ErrUnexpectedEOF, "buffer is too small for key exchange")
	}

	entry.KeyExchange = make([]byte, keyLen)
	copy(entry.KeyExchange, data[4:keyLen+4])

	return nil
}

// KeyShareEntryList represents a list of
// individual public keys that belong to
// unique key types
type KeyShareEntryList []KeyShareEntry

// Size returns the number of bytes that would
// be produced if the list was to be marshaled to
// a binary format
func (list KeyShareEntryList) Size() (size uint16) {
	for i := range list {
		size += list[i].Size()
	}

	return
}

func (list KeyShareEntryList) String() string {
	var builder strings.Builder
	builder.WriteString("[")

	for i := range list {
		if i > 0 {
			builder.WriteString(", ")
		}

		_, _ = fmt.Fprintf(&builder, "{Group:%s, Value:%s}", list[i].Group, hex.EncodeToString(list[i].KeyExchange))
	}

	builder.WriteString("]")
	return builder.String()
}

// Contains checks if the list already contains
// a key share entry with the same group type
func (list KeyShareEntryList) Contains(entry KeyShareEntry) bool {
	for i := range list {
		if list[i].Group == entry.Group {
			return true
		}
	}

	return false
}

// MarshalBinary attempts to marshal the list of
// key share entries into a binary format for inclusion
// in a ESNI keys record
func (list KeyShareEntryList) MarshalBinary() ([]byte, error) {
	data := make([]byte, list.Size())

	var pos int
	for i := range list {
		entry, err := list[i].MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "marshal key share entry")
		}

		pos += copy(data[pos:], entry)
	}

	return data, nil
}

// UnmarshalBinary attempts to unmarshal a list of
// key share entries from the provided binary data
func (list *KeyShareEntryList) UnmarshalBinary(data []byte) error {
	for pos := 0; pos < len(data); {
		entry := KeyShareEntry{}
		if err := entry.UnmarshalBinary(data[pos:]); err != nil {
			return errors.Wrap(err, "unmarshal key share entry")
		}

		if list.Contains(entry) {
			return errors.New("duplicate key share group")
		}

		pos += int(entry.Size()) + 1
		*list = append(*list, entry)
	}

	return nil
}
