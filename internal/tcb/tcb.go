package tcb

// TCBVersion represents the components packed into AMD SEV-SNP's 64-bit
// TCB version number. Each field is a Security Version Number (SVN) for a
// specific firmware component. Higher SVN = more recent patches.
//
// Bit layout (AMD SEV-SNP ABI spec §8.3):
//   Bits  7:0  — BootloaderSVN (BIOS/UEFI bootloader)
//   Bits 15:8  — TEESVN        (AMD Trusted Execution Environment firmware)
//   Bits 47:16 — reserved
//   Bits 55:48 — SNPSVN        (AMD SEV-SNP firmware)
//   Bits 63:56 — MicrocodeSVN  (CPU microcode)
type TCBVersion struct {
	BootloaderSVN uint8
	TEESVN        uint8
	SNPSVN        uint8
	MicrocodeSVN  uint8
}

// ParseTCB unpacks a raw 64-bit TCB value into its individual SVN components.
func ParseTCB(raw uint64) TCBVersion {
	return TCBVersion{
		BootloaderSVN: uint8(raw),
		TEESVN:        uint8(raw >> 8),
		SNPSVN:        uint8(raw >> 48),
		MicrocodeSVN:  uint8(raw >> 56),
	}
}

// VerifyTCB returns true if every SVN component in actual is greater than or
// equal to the corresponding component in minimum. Checking each component
// independently is required because a single uint64 comparison would give
// wrong results — e.g. a high MicrocodeSVN could mask a too-low SNPSVN.
func VerifyTCB(actual, minimum uint64) bool {
	a := ParseTCB(actual)
	m := ParseTCB(minimum)
	return a.BootloaderSVN >= m.BootloaderSVN &&
		a.TEESVN >= m.TEESVN &&
		a.SNPSVN >= m.SNPSVN &&
		a.MicrocodeSVN >= m.MicrocodeSVN
}
