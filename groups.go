package esni

// Group represents a specific public
// key type
type Group uint16

const (
	GroupECP256R1  Group = 0x0017
	GroupSECP384R1       = 0x0018
	GroupSECP521R1       = 0x0019
	GroupX25519          = 0x001D
	GroupX448            = 0x001E
	GroupFFDHE2048       = 0x1000
	GroupFFDHE3072       = 0x1001
	GroupFFDHE4096       = 0x1002
	GroupFFDHE6144       = 0x1003
	GroupFFDHE8192       = 0x1004
)

// Group_name defines a map of groups
// and their respective string representations
var Group_name = map[Group]string{
	GroupECP256R1:  "ecp256r1",
	GroupSECP384R1: "secp384r1",
	GroupSECP521R1: "secp521r1",
	GroupX25519:    "x25519",
	GroupX448:      "x448",
	GroupFFDHE2048: "ffdhe2048",
	GroupFFDHE3072: "ffdhe3072",
	GroupFFDHE4096: "ffdhe4096",
	GroupFFDHE6144: "ffdhe6144",
	GroupFFDHE8192: "ffdhe8192",
}

// String attempts to return the string
// representation of the Group based on
// those specified in Group_name, if no
// match is found "UNKNOWN" is returned
func (g Group) String() string {
	if name, ok := Group_name[g]; ok {
		return name
	}

	return "UNKNOWN"
}
