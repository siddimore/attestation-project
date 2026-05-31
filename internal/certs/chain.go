package certs

import (
	"crypto/x509"
	"errors"
	"fmt"
)

func VerifyCertificateChain(ark, ask, vcek *x509.Certificate) error {

	if !ark.IsCA {
		return errors.New(
			"ARK is not a CA",
		)
	}

	if err := ask.CheckSignatureFrom(ark); err != nil {
		return fmt.Errorf("Error verifying intermediate CA")
	}

	if err := vcek.CheckSignatureFrom(ask); err != nil {
		return fmt.Errorf("Error verifying vcek")
	}

	return nil
}
