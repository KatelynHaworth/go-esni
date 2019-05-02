package esni

import (
	"bytes"
	"errors"
	"net"
	"strings"
)

// init is called when the package is first
// imported in the runtime, it allows of the
// dynamic registration of ESNI extension types
func init() {
	RegisterExtensionType(ExtensionTypeAddressSet, "address_set", func() Extension { return new(AddressSet) })
}

const (
	ExtensionTypeAddressSet ExtensionType = 0x1001
)

// AddressSet represents an ESNI extension
// that defines a set of IP addresses for servers
// that support the keys specified by the
// parent ESNI keys record
type AddressSet struct {
	Addresses []net.IP
}

// Type returns the unique identifier
// for the ESNI extension
func (*AddressSet) Type() ExtensionType {
	return ExtensionTypeAddressSet
}

// Size returns the number of bytes that would
// be produced if the extension were to be marshaled
// to it's binary format
func (set *AddressSet) Size() (size uint16) {
	for i := range set.Addresses {
		size += 1

		if set.Addresses[i].To4() != nil {
			size += net.IPv4len
		} else {
			size += net.IPv6len
		}
	}

	return
}

// MarshalBinary will marshal the ESNI extension
// value to a binary format for inclusion in an
// extension list
func (set *AddressSet) MarshalBinary() ([]byte, error) {
	data := bytes.NewBuffer(make([]byte, set.Size()))

	for i := range set.Addresses {
		if ipv4 := set.Addresses[i].To4(); ipv4 != nil {
			data.WriteByte(4)
			data.Write(ipv4)
		} else {
			data.WriteByte(6)
			data.Write(set.Addresses[i])
		}
	}

	return data.Bytes(), nil
}

// UnmarshalBinary will attempt to unmarshal the
// ESNI extension value from the provided binary
// data
func (set *AddressSet) UnmarshalBinary(data []byte) error {
	for pos := 0; pos < len(data); {
		switch data[pos] {
		case 4:
			address := make(net.IP, net.IPv4len)
			copy(address, data[pos+1:])

			set.Addresses = append(set.Addresses, address)
			pos += net.IPv4len + 1

		case 6:
			address := make(net.IP, net.IPv6len)
			copy(address, data[pos+1:])

			set.Addresses = append(set.Addresses, address)
			pos += net.IPv6len + 1

		default:
			return errors.New("unsupported address type")
		}
	}

	return nil
}

// String returns a friendly representation of
// the ESNI extension value
func (set *AddressSet) String() string {
	var builder strings.Builder
	builder.WriteString("[")

	for i := range set.Addresses {
		if i > 0 {
			builder.WriteString(", ")
		}

		if ipv4 := set.Addresses[i].To4(); ipv4 != nil {
			builder.WriteString("IPv4:")
			builder.WriteString(ipv4.String())
		} else {
			builder.WriteString("IPv6:")
			builder.WriteString(set.Addresses[i].String())
		}
	}

	builder.WriteString("]")
	return builder.String()
}
