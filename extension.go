package esni

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

const (
	// mandatoryExtensionMask is used in an
	// AND bitwise operation to check if the
	// highest bit is set
	mandatoryExtensionMask uint16 = 4096
)

var (
	// ErrUnsupportedExtensionType is returned by
	// UnmarshalBinary on ExtensionList if it
	// encounters an extension type it is unable
	// to unmarshal.
	//
	// The ESNI specification states that clients
	// MUST fail if they encounter an unsupported
	// extension type, this error is to ensure the
	// ESNI record stops unmarshalling when this occurs.
	ErrUnsupportedExtensionType = errors.New("unsupported extension type")

	// ExtensionType_generator defines a map of
	// extension types to their respective generator
	// function
	ExtensionType_generator = map[ExtensionType]func() Extension{}

	// ExtensionType_name defines a map of extension
	// types to their respective string representation
	ExtensionType_name = map[ExtensionType]string{}
)

// ExtensionType represents the unique
// identifier of a specific ESNI extension
type ExtensionType uint16

// RegisterExtensionType will register the
// name and generator function for a specific
// extension type
func RegisterExtensionType(extType ExtensionType, name string, generator func() Extension) {
	if _, exists := ExtensionType_generator[extType]; exists {
		panic("extension type already registered")
	}

	ExtensionType_name[extType] = name
	ExtensionType_generator[extType] = generator
}

// Mandatory returns if the inclusion,
// or use, of an extension is mandatory
// in the preparation of a ClientHello.
//
// An extension type is classified as
// mandatory if the highest bit is set
// to 1.
func (extType ExtensionType) Mandatory() bool {
	return uint16(extType)&mandatoryExtensionMask == mandatoryExtensionMask
}

// String attempts to return the string
// representation of the ExtensionType based
// on those specified in ExtensionType_name,
// if no match is found "UNKNOWN" is returned
func (extType ExtensionType) String() string {
	if name, ok := ExtensionType_name[extType]; ok {
		return name
	}

	return "UNKNOWN"
}

// Generator attempts to return the generator
// function for the ExtensionType based on those
// specified in ExtensionType_generator, if no
// match is found, nil is returned.
//
// The generator function can be used to create
// a new instance of the extension for the purpose
// of unmarshalling.
func (extType ExtensionType) Generator() func() Extension {
	if gen, ok := ExtensionType_generator[extType]; ok {
		return gen
	}

	return nil
}

// Extension specifies the methods a
// structure must implement to be treated
// as a ESNI extension
type Extension interface {
	// Type must return the unique type
	// identifier for the extension
	Type() ExtensionType

	// Size must return the number of bytes
	// that marshalling the extension to binary
	// would produce
	Size() uint16

	// The extension must provide the ability
	// to marshal and unmarshal itself from
	// binary data
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	// The extension must provide a String()
	// method that produces a log friendly
	// representation of the extension data
	fmt.Stringer
}

// ExtensionList represents a list of
// ESNI extensions present in a ESNI
// Keys record
type ExtensionList []Extension

// String will produce a friendly representation
// of the extension list and the extensions contained
// within
func (list ExtensionList) String() string {
	var builder strings.Builder
	builder.WriteString("[")

	for i := range list {
		if i > 0 {
			builder.WriteString(", ")
		}
		_, _ = fmt.Fprintf(&builder, "{Type:%s, Mandatory:%t, Value:%s}", list[i].Type(), list[i].Type().Mandatory(), list[i])
	}

	builder.WriteString("]")
	return builder.String()
}

// Size returns the number of bytes that
// marshalling the extension to its binary
// format would produce
func (list ExtensionList) Size() (size uint16) {
	for i := range list {
		size += 2
		size += list[i].Size()
	}

	return
}

// MarshalBinary marshals the list of ESNI
// extensions into a binary format of each
// extension type and their respective marshaled
// format
func (list ExtensionList) MarshalBinary() ([]byte, error) {
	buffer := bytes.NewBuffer(make([]byte, list.Size()))

	for i := range list {
		if err := binary.Write(buffer, binary.BigEndian, list[i].Type()); err != nil {
			return nil, errors.Wrap(err, "write extension type")
		}

		extData, err := list[i].MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "marshal extension")
		}

		if _, err := buffer.Write(extData); err != nil {
			return nil, errors.Wrap(err, "write extension data")
		}
	}

	return buffer.Bytes(), nil
}

// UnmarshalBinary unmarshals an extension list
// from the provided data buffer, for each extension
// type read, the respective extension implementation
// will be called to be unmarshaled
func (list *ExtensionList) UnmarshalBinary(data []byte) error {
	for pos := 0; pos < len(data); {
		extType := ExtensionType(binary.BigEndian.Uint16(data[pos:]))

		gen := extType.Generator()
		if gen == nil {
			return errors.Wrapf(ErrUnsupportedExtensionType, "extension_type(%d)", extType)
		}

		ext := gen()
		if err := ext.UnmarshalBinary(data[pos+2:]); err != nil {
			return errors.Wrap(err, "unmarshal extension")
		}

		*list = append(*list, ext)
		pos += int(ext.Size()) + 2
	}

	return nil
}
