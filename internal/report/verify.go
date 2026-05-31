package report

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
)

func (atr *AttestationReport) VerifyReportSignature(vcek *x509.Certificate) error {
	reportBytes, _ := json.Marshal(atr)
	digest := sha256.Sum256(reportBytes)

	sig, err := os.ReadFile("testdata/report.sig")
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	pub, ok := vcek.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("VCEK public key is not ECDSA")
	}

	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("report signature is invalid")
	}

	fmt.Println("report signature valid")
	return nil
}
