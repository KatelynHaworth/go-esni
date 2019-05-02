package esni

// CipherSuite represents a specific
// TLS cipher and signature set
type CipherSuite uint16

const (
	CipherSuite_TLS_AES_128_GCM_SHA256       CipherSuite = 0x1301
	CipherSuite_TLS_AES_256_GCM_SHA384                   = 0x1302
	CipherSuite_TLS_CHACHA20_POLY1305_SHA256             = 0x1303
	CipherSuite_TLS_AES_128_CCM_SHA256                   = 0x1304
	CipherSuite_TLS_AES_128_CCM_8_SHA256                 = 0x1305
)

// CipherSuite_name specifies a map of CipherSuites
// to their respective string representation
var CipherSuite_name = map[CipherSuite]string{
	CipherSuite_TLS_AES_128_GCM_SHA256:       "TLS_AES_128_GCM_SHA256",
	CipherSuite_TLS_AES_256_GCM_SHA384:       "TLS_AES_256_GCM_SHA384",
	CipherSuite_TLS_CHACHA20_POLY1305_SHA256: "TLS_CHACHA20_POLY1305_SHA256",
	CipherSuite_TLS_AES_128_CCM_SHA256:       "TLS_AES_128_CCM_SHA256",
	CipherSuite_TLS_AES_128_CCM_8_SHA256:     "TLS_AES_128_CCM_8_SHA256",
}

// String attempts to return the string
// representation of the CipherSuite based
// on those specified in Version_name, if no
// match is found "UNKNOWN" is returned
func (suite CipherSuite) String() string {
	if name, ok := CipherSuite_name[suite]; ok {
		return name
	}

	return "UNKNOWN"
}