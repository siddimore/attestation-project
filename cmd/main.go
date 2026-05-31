package main

import (
	"fmt"
	"mini-attestation/internal/certs"
	"mini-attestation/internal/policy"
	"mini-attestation/internal/report"
	"mini-attestation/internal/secret"
	"mini-attestation/internal/utils"
)

func main() {
	fakeKDS := certs.FakeKDS{}
	arkPEM, err := fakeKDS.GetARK()
	if err != nil {
		panic(fmt.Sprintf("failed to load ARK: %v", err))
	}
	askPEM, err := fakeKDS.GetASK()
	if err != nil {
		panic(fmt.Sprintf("failed to load ASK: %v", err))
	}
	vcekPEM, err := fakeKDS.GetVCEK()
	if err != nil {
		panic(fmt.Sprintf("failed to load VCEK: %v", err))
	}

	// 2. Parse PEM data into Go x509 structures
	arkCert, err := utils.ParsePEMToX509(arkPEM)
	if err != nil {
		panic(fmt.Sprintf("ARK parsing error: %v", err))
	}
	askCert, err := utils.ParsePEMToX509(askPEM)
	if err != nil {
		panic(fmt.Sprintf("ASK parsing error: %v", err))
	}
	vcekCert, err := utils.ParsePEMToX509(vcekPEM)
	if err != nil {
		panic(fmt.Sprintf("VCEK parsing error: %v", err))
	}

	if err := certs.VerifyCertificateChain(
		arkCert,
		askCert,
		vcekCert,
	); err != nil {

		panic(err)
	}

	fmt.Println("certificate chain verified")

	// The verifier generates a fresh challenge nonce and sends it to the guest
	// before requesting the report. The guest embeds it in REPORT_DATA so the
	// returned report is bound to this session and cannot be replayed.
	challengeNonce := "test"

	//{"measurement":"abc123","tcb":5}
	attReport := report.AttestationReport{
		Measurement: "abc123",
		TCB:         5,
		Nonce:       challengeNonce,
	}
	err = attReport.VerifyReportSignature(vcekCert)
	if err != nil {
		panic(err)
	}

	p := &policy.Policy{
		AllowedMeasurements: []string{"abc123"},
		MinimumTCB:          5,
		ExpectedNonce:       challengeNonce,
	}
	if err := p.EvaluateReport(&attReport); err != nil {
		panic(err)
	}

	// Only release the secret after all attestation checks have passed.
	// In a real system this would be a KMS-sealed key unwrapped here.
	protectedSecret := &secret.Secret{Value: "super-secret-key-material"}
	keyMaterial, err := protectedSecret.Release(true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("secret released: %s\n", keyMaterial)

	fmt.Println("Finished Validation")
}
