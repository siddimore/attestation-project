package secret

import "fmt"

// Secret represents a sensitive value that should only be released after
// successful attestation — for example, a disk-encryption key, a TLS private
// key, or an API credential.
//
// In a real deployment this would be an opaque blob retrieved from a KMS
// (e.g. Azure mHSM, AWS KMS, or Vault) after the attestation token is
// validated server-side. Here we model it as a plain string for demo purposes.
type Secret struct {
	Value string
}

// Release returns the secret value if attestation succeeded (trusted == true).
// If the attestation result is not trusted, it returns an error so the caller
// is forced to handle the failure rather than silently receiving an empty value.
//
// This is the final gate in the attestation flow: even if the cert chain and
// report signature check out, the policy evaluation result must be passed here
// to actually obtain the protected material.
func (s *Secret) Release(trusted bool) (string, error) {
	if !trusted {
		return "", fmt.Errorf("attestation failed: refusing to release secret")
	}
	return s.Value, nil
}

// ShouldReleaseSecret is a convenience helper for callers that only need a
// boolean decision without holding a Secret value.
func ShouldReleaseSecret(trusted bool) bool { return trusted }
