package esni

// Version represents a specific ESNI
// specification version for the DNS
// ESNI record
type Version uint16

const (
	// VersionDraft01 represents the version value
	// for the first draft of the ESNI specification.
	//
	// The version value specified in the second version
	// of the draft is the same as the first draft.
	VersionDraft01 Version = 0xff01

	// VersionDraft03 represents the version value
	// for the third draft of the ESNI specification
	VersionDraft03 Version = 0xff02
)

// Version_name specifies a map of versions
// and their respective string representations
var Version_name = map[Version]string{
	VersionDraft01: "draft-ietf-tls-esni-01",
	VersionDraft03: "draft-ietf-tls-esni-03",
}

// String attempts to return the string
// representation of the Version based on
// those specified in Version_name, if no
// match is found "UNKNOWN" is returned
func (v Version) String() string {
	if name, ok := Version_name[v]; ok {
		return name
	}

	return "UNKNOWN"
}
