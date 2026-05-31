package report

import "fmt"

// AttestationReport is a simplified representation of an AMD SEV-SNP
// attestation report. In hardware, the full report is a 1184-byte structure
// signed by the VCEK. Here we model only the fields relevant to this demo.
//
// Measurement is the SHA-384 digest of the initial guest memory, computed by
// the AMD Secure Processor at launch time. It uniquely identifies the workload.
//
// TCB is the platform's current TCB version — a packed uint64 encoding
// individual firmware SVN components (see internal/tcb for the breakdown).
//
// Nonce (REPORT_DATA in the hardware spec) is 64 bytes of caller-supplied data
// included verbatim in the signed report. Typically set to a challenge nonce
// or the hash of an ephemeral public key to bind the report to a session and
// prevent replay attacks. Excluded from JSON marshaling since our pre-generated
// testdata/report.json does not include it.
//
// Signature holds the raw ECDSA-P256 ASN.1 DER signature over the report.
// Excluded from JSON marshaling so it is not part of the signed payload.
type AttestationReport struct {
	Measurement string `json:"measurement"`
	TCB         uint64 `json:"tcb"`
	Nonce       string `json:"-"`
	Signature   []byte `json:"-"`
}

// VerifyNonce checks that the nonce embedded in the report matches the
// expected challenge issued by the verifier. This prevents an attacker from
// replaying a previously captured valid report.
func (atr *AttestationReport) VerifyNonce(expected string) error {
	if atr.Nonce != expected {
		return fmt.Errorf("nonce mismatch: report contains %q, expected %q", atr.Nonce, expected)
	}
	return nil
}
