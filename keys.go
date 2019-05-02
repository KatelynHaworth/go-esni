package esni

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
)

var (
	// ErrChecksumMismatch is returned during unmarshalling
	// of a ESNI Keys record when the body of the record
	// doesn't match the checksum included in the record
	ErrChecksumMismatch = errors.New("calculated checksum did not match received checksum")
)

// Keys represents a ENSIKeys record used
// to specify information to be used to encrypt
// an SNI with a specific server
type Keys struct {
	// Version specifies the ESNI specification version
	// the Keys record conforms too
	Version Version

	// Checksum is the first 4 bytes of a SHA-256
	// sum of the binary Keys record, this field
	// is ignored during marshalling
	Checksum [4]byte

	// PublicName specifies the clear text SNI that
	// should be utilized during the TLS handshake
	// to allow for intermediate servers to handle
	// the request before being forwarded to the backend
	// server
	PublicName string

	// Keys defines a list of individual
	// public keys that are permitted to
	// be used for generating the shared
	// encryption secret
	Keys KeyShareEntryList

	// CipherSuites defines a list of cipher
	// suites that are permitted to be used
	// for the encryption of the SNI
	CipherSuites []CipherSuite

	// PaddedLength specifies the required length
	// of the encrypted SNI, if the SNI is smaller
	// than the padded length it must be combined
	// with extra zero data to match the padded
	// length before encryption
	PaddedLength uint16

	// NotBefore specifies the time at which the
	// keys in this record are valid for use
	NotBefore time.Time

	// NotAfter specifies the time at which the keys
	// in this record are no longer valid of use
	NotAfter time.Time

	// Extensions specifies a list of extensions
	// to the ESNI specification to provide extra
	// information to the client
	Extensions ExtensionList
}

// String returns a friendly representation
// of the information stored in this structure
func (keys *Keys) String() string {
	var builder strings.Builder
	builder.WriteString("{")

	_, _ = fmt.Fprintf(&builder, "Version:%s, ", keys.Version)
	_, _ = fmt.Fprintf(&builder, "Checksum:%s, ", hex.EncodeToString(keys.Checksum[:]))

	if keys.Version >= VersionDraft03 {
		_, _ = fmt.Fprintf(&builder, "PublicName:%s, ", keys.PublicName)
	}

	_, _ = fmt.Fprintf(&builder, "Keys:%s, ", keys.Keys)
	_, _ = fmt.Fprintf(&builder, "CipherSuites:%s, ", keys.CipherSuites)
	_, _ = fmt.Fprintf(&builder, "PaddedLength:%d, ", keys.PaddedLength)
	_, _ = fmt.Fprintf(&builder, "NotBefore:%s, ", keys.NotBefore)
	_, _ = fmt.Fprintf(&builder, "NotAfter:%s, ", keys.NotAfter)
	_, _ = fmt.Fprintf(&builder, "Extensions:%s", keys.Extensions)

	builder.WriteString("}")
	return builder.String()
}

// MarshalBinary will attempt to marshal the contents
// of the Keys record into a binary format specified
// by the ESNI specification
func (keys Keys) MarshalBinary() ([]byte, error) {
	var data bytes.Buffer

	if err := binary.Write(&data, binary.BigEndian, keys.Version); err != nil {
		return nil, errors.Wrap(err, "write version")
	}

	if _, err := data.Write([]byte{0x0, 0x0, 0x0, 0x0}); err != nil {
		return nil, errors.Wrap(err, "write empty checksum")
	}

	if err := keys.marshalPublicName(&data); err != nil {
		return nil, errors.Wrap(err, "marshal public name")
	}

	if err := keys.marshalKeyShareList(&data); err != nil {
		return nil, errors.Wrap(err, "marshal key share list")
	}

	if err := keys.marshalCipherSuites(&data); err != nil {
		return nil, errors.Wrap(err, "marshal cipher suite list")
	}

	if err := binary.Write(&data, binary.BigEndian, keys.PaddedLength); err != nil {
		return nil, errors.Wrap(err, "write padded length")
	}

	if err := keys.marshalValidityPeriod(&data); err != nil {
		return nil, errors.Wrap(err, "marshal validity period")
	}

	if err := keys.marshalExtensions(&data); err != nil {
		return nil, errors.Wrap(err, "marshal extensions list")
	}

	final := data.Bytes()
	sum := sha256.Sum256(final)

	copy(final[2:6], sum[:4])
	return final, nil
}

// UnmarshalBinary will attempt to unmarshal and parse
// information about a Keys record from the binary data
// provided
func (keys *Keys) UnmarshalBinary(b []byte) error {
	keys.Version = Version(binary.BigEndian.Uint16(b[0:]))

	copy(keys.Checksum[:], b[2:])
	copy(b[2:], []byte{0x00, 0x00, 0x00, 0x00})

	sum := sha256.Sum256(b)
	if bytes.Compare(keys.Checksum[:], sum[:4]) != 0 {
		return ErrChecksumMismatch
	}

	reader := bytes.NewReader(b[6:])
	if err := keys.unmarshalPublicName(reader); err != nil {
		return errors.Wrap(err, "unmarshal public name")
	}

	if err := keys.unmarshalKeyShareList(reader); err != nil {
		return errors.Wrap(err, "unmarshal key share list")
	}

	if err := keys.unmarshalCipherSuites(reader); err != nil {
		return errors.Wrap(err, "unmarshal cipher suite list")
	}

	if err := binary.Read(reader, binary.BigEndian, &keys.PaddedLength); err != nil {
		return errors.Wrap(err, "read padded length")
	}

	if err := keys.unmarshalValidityPeriod(reader); err != nil {
		return errors.Wrap(err, "unmarshal validity period")
	}

	if err := keys.unmarshalExtensions(reader); err != nil {
		return errors.Wrap(err, "unmarshal extensions list")
	}

	return nil
}

// marshalPublicName will write the length of
// the public name field along with the value
// of the field
func (keys Keys) marshalPublicName(data *bytes.Buffer) error {
	// TODO(lh): Once the ESNI specific leaves draft
	//           status this will need to be removed
	//           as it will most likely be mandatory
	//           for all versions
	if keys.Version < VersionDraft03 {
		return nil
	}

	if len(keys.PublicName) == 0 {
		return errors.New("public name is empty")
	} else if len(keys.PublicName) > 255 {
		return errors.New("public name is too large")
	}

	if err := data.WriteByte(uint8(len(keys.PublicName))); err != nil {
		return errors.Wrap(err, "write public name length")
	}

	if _, err := data.WriteString(keys.PublicName); err != nil {
		return errors.Wrap(err, "write public name")
	}

	return nil
}

// unmarshalPublicName will read the length of
// the public name and attempt to read the public
// name
func (keys *Keys) unmarshalPublicName(reader *bytes.Reader) error {
	// TODO(lh): Once the ESNI specific leaves draft
	//           status this will need to be removed
	//           as it will most likely be mandatory
	//           for all versions
	if keys.Version < VersionDraft03 {
		return nil
	}

	nameLength, err := reader.ReadByte()
	if err != nil {
		return errors.Wrap(err, "read length")
	}

	if nameLength == 0 {
		return errors.New("public name is empty")
	}

	name := make([]byte, nameLength)
	if _, err := reader.Read(name); err != nil {
		return err
	}

	keys.PublicName = string(name)
	return nil
}

// marshalKeyShareList will write the binary length
// of the entry list and marshal the list to binary
// format, writing it to the buffer
func (keys Keys) marshalKeyShareList(data *bytes.Buffer) error {
	if len(keys.Keys) == 0 {
		return errors.New("key share list is empty")
	}

	if err := binary.Write(data, binary.BigEndian, keys.Keys.Size()); err != nil {
		return errors.Wrap(err, "write key share list size")
	}

	listData, err := keys.Keys.MarshalBinary()
	if err != nil {
		return err
	}

	if _, err := data.Write(listData); err != nil {
		return errors.Wrap(err, "write key share list")
	}

	return nil
}

// unmarshalKeyShareList will read the length of the
// entry list and attempt to unmarshal a KeyShareEntryList
// from the read data
func (keys *Keys) unmarshalKeyShareList(reader *bytes.Reader) error {
	var listLen uint16
	if err := binary.Read(reader, binary.BigEndian, &listLen); err != nil {
		return errors.Wrap(err, "read key share list size")
	}

	if listLen == 0 {
		return errors.New("key share list is empty")
	}

	data := make([]byte, listLen)
	if _, err := reader.Read(data); err != nil {
		return errors.Wrap(err, "read key share list")
	}

	keys.Keys = make(KeyShareEntryList, 0)
	if err := keys.Keys.UnmarshalBinary(data); err != nil {
		return err
	}

	return nil
}

// marshalCipherSuites will write the binary size
// of the cipher suite list and unique identifier
// for each supported cipher suite
func (keys Keys) marshalCipherSuites(data *bytes.Buffer) error {
	if err := binary.Write(data, binary.BigEndian, uint16(len(keys.CipherSuites)*2)); err != nil {
		return errors.Wrap(err, "write cipher suite list size")
	}

	for i := range keys.CipherSuites {
		if err := binary.Write(data, binary.BigEndian, keys.CipherSuites[i]); err != nil {
			return errors.Wrap(err, "write cipher suite")
		}
	}

	return nil
}

// unmarshalCipherSuites will read the binary length
// of the cipher suite list and will read each individual
// cipher
func (keys *Keys) unmarshalCipherSuites(reader *bytes.Reader) error {
	var suitesLen uint16
	if err := binary.Read(reader, binary.BigEndian, &suitesLen); err != nil {
		return errors.Wrap(err, "read cipher suite list size")
	}

	if suitesLen%2 != 0 {
		return errors.New("invalid cipher suite list size")
	}

	keys.CipherSuites = make([]CipherSuite, suitesLen/2)
	for i := range keys.CipherSuites {
		var suite uint16
		if err := binary.Read(reader, binary.BigEndian, &suite); err != nil {
			return errors.Wrapf(err, "read cipher suite %d", i)
		}

		keys.CipherSuites[i] = CipherSuite(suite)
	}

	return nil
}

// marshalValidityPeriod will write the not before
// and not after fields as uint64 binary variables
func (keys Keys) marshalValidityPeriod(data *bytes.Buffer) error {
	if err := binary.Write(data, binary.BigEndian, uint64(keys.NotBefore.Unix())); err != nil {
		return errors.Wrap(err, "write not before")
	}

	if err := binary.Write(data, binary.BigEndian, uint64(keys.NotAfter.Unix())); err != nil {
		return errors.Wrap(err, "write not after")
	}

	return nil
}

// unmarshalValidityPeriod will read the not before
// and not after fields from the binary data
func (keys *Keys) unmarshalValidityPeriod(reader *bytes.Reader) error {
	var notBefore, notAfter uint64

	if err := binary.Read(reader, binary.BigEndian, &notBefore); err != nil {
		return errors.Wrap(err, "read not before")
	}

	if err := binary.Read(reader, binary.BigEndian, &notAfter); err != nil {
		return errors.Wrap(err, "read not after")
	}

	keys.NotBefore = time.Unix(int64(notBefore), 0)
	keys.NotAfter = time.Unix(int64(notAfter), 0)

	return nil
}

// marshalExtensions will write the binary size of
// the extensions list and will marshal the list to
// binary format, writing it to the buffer
func (keys *Keys) marshalExtensions(data *bytes.Buffer) error {
	if err := binary.Write(data, binary.BigEndian, keys.Extensions.Size()); err != nil {
		return errors.Wrap(err, "write extensions list length")
	}

	if len(keys.Extensions) == 0 {
		return nil
	}

	extsData, err := keys.Extensions.MarshalBinary()
	if err != nil {
		return err
	}

	if _, err := data.Write(extsData); err != nil {
		return errors.Wrap(err, "write extensions list")
	}

	return nil
}

// unmarshalExtensions will read the binary length of
// the extensions list and will attempt to unmarshal
// a ExtensionList from that data
func (keys *Keys) unmarshalExtensions(reader *bytes.Reader) error {
	var extsLen uint16
	if err := binary.Read(reader, binary.BigEndian, &extsLen); err != nil {
		return errors.Wrap(err, "read extensions list length")
	}

	if extsLen == 0 {
		return nil
	}

	extsData := make([]byte, extsLen)
	if _, err := reader.Read(extsData); err != nil {
		return errors.Wrap(err, "read extensions list")
	}

	keys.Extensions = make(ExtensionList, 0)
	if err := keys.Extensions.UnmarshalBinary(extsData); err != nil {
		return err
	}

	return nil
}