package policy

import (
	"fmt"
	"mini-attestation/internal/report"
	"mini-attestation/internal/tcb"
)

// Policy defines the rules an attestation report must satisfy.
// AllowedMeasurements is the set of accepted workload measurement values.
// MinimumTCB is the lowest TCB version considered secure; each SVN component
// in the report's TCB must be >= the corresponding component in MinimumTCB.
// ExpectedNonce is the challenge nonce the verifier sent to the guest; if set,
// the report's Nonce field must match exactly to prevent replay attacks.
type Policy struct {
	AllowedMeasurements []string
	MinimumTCB          uint64
	ExpectedNonce       string
}

// EvaluateReport checks that the given AttestationReport satisfies the policy.
// It returns an error describing the first violation found, or nil if the
// report is compliant.
func (p *Policy) EvaluateReport(r *report.AttestationReport) error {
	// Verify the workload measurement is in the allowlist.
	allowed := false
	for _, m := range p.AllowedMeasurements {
		if m == r.Measurement {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("measurement %q is not in the allowed list", r.Measurement)
	}

	// Verify the TCB version meets the minimum required level.
	if !tcb.VerifyTCB(r.TCB, p.MinimumTCB) {
		return fmt.Errorf("TCB %d is below minimum required %d", r.TCB, p.MinimumTCB)
	}

	// Verify the nonce matches the challenge issued by the verifier.
	if p.ExpectedNonce != "" {
		if err := r.VerifyNonce(p.ExpectedNonce); err != nil {
			return err
		}
	}

	return nil
}
