# AMD SEV-SNP Mini Attestation Service

A minimal Go implementation of the AMD SEV-SNP remote attestation flow — certificate chain verification, report signature checking, TCB policy evaluation, and secret release.

---

## What is AMD SEV-SNP?

**SEV** = Secure Encrypted Virtualization  
**SNP** = Secure Nested Paging

Together they form AMD's confidential-computing hardware feature set available on EPYC processors (Milan/Genoa/Bergamo families).

| Layer | What it does |
|---|---|
| **SEV** | Encrypts each VM's memory with a unique key managed by the AMD Secure Processor (ASP). The hypervisor can no longer read guest RAM in plaintext. |
| **ES** (Encrypted State) | Also encrypts CPU register state (VMSA) on every VM exit so the hypervisor cannot inspect registers. |
| **SNP** | Adds memory integrity protection via a Reverse Map Table (RMP). Every memory page is tagged with its owner; a rogue hypervisor attempting to alias or remap guest pages causes a hardware fault. SNP also introduces the **attestation report** — a hardware-signed statement about what is running and at what firmware level. |

The result: a VM's confidentiality and integrity are enforced by silicon, not by the cloud provider's software stack.

---

## Key Concepts

### The AMD Secure Processor (ASP)

A dedicated ARM Cortex-A5 security co-processor embedded on every AMD EPYC die. It:
- Manages all per-VM encryption keys.
- Generates attestation reports on behalf of the guest.
- Holds the per-chip private key used to sign those reports.
- Never exposes private key material to software — not even to the hypervisor or the guest OS.

### The Attestation Report

When a guest calls `SNP_GET_REPORT` (via the `sev-guest` kernel driver), the ASP produces a **1184-byte signed structure** containing:

| Field | Meaning |
|---|---|
| `MEASUREMENT` | SHA-384 of initial guest memory at launch, computed by the ASP. Uniquely identifies the workload binary. |
| `REPORT_DATA` | 64 bytes supplied by the guest — typically a challenge nonce or hash of an ephemeral public key. Binds the report to a session. |
| `TCB_VERSION` | Packed uint64 of per-component firmware Security Version Numbers (SVNs) at signing time. |
| `SIGNATURE` | ECDSA-P384 signature over the report body, made with the chip's VCEK or VLEK private key. |

---

## The Certificate Chain: ARK → ASK → VCEK

AMD uses a three-level X.509 certificate hierarchy to bind every chip's signing key back to AMD's own root.

```
AMD Root Key (ARK)          — AMD's offline root CA
        │  signs
        ▼
AMD SEV Key (ASK)           — AMD's intermediate CA, one per CPU family/generation
        │  signs
        ▼
Versioned Chip Endorsement Key (VCEK)   — one per physical chip, per TCB version
```

### ARK — AMD Root Key

- A **self-signed** root CA certificate.
- The private key is held in an air-gapped HSM at AMD.
- AMD publishes ARK certificates on their Key Distribution Service (KDS). There is one ARK per CPU product line (e.g., Milan, Genoa).
- **You trust AMD** by pinning this certificate. It never changes for a given product family.

### ASK — AMD SEV Key

- An **intermediate CA** certificate signed by the ARK.
- One ASK exists per CPU generation / stepping.
- AMD publishes ASK certificates alongside ARK on the KDS.
- Its role is solely to sign VCEK certificates; it never signs attestation reports directly.

### VCEK — Versioned Chip Endorsement Key

- A **leaf certificate** unique to a specific physical chip **at a specific TCB version**.
- Contains an **ECDSA-P384 public key** whose private counterpart lives exclusively inside the ASP and is never exported.
- The `subjectAltName` extension encodes the chip's `CHIP_ID` (a hardware-derived identifier) and the TCB version (bootloader SVN, TEE SVN, SNP SVN, microcode SVN) as custom OID extensions.
- Because it is TCB-versioned, when firmware is patched a **new VCEK certificate** is issued by AMD for the same chip at the new TCB level. Old VCEK certificates for older TCB levels remain valid but a policy can reject them.
- The ASP uses the VCEK private key to sign every attestation report.

### How VCEK Is Obtained in Production

The relying party (verifier) fetches the VCEK from AMD's **Key Distribution Service (KDS)**:

```
GET https://kdsintf.amd.com/vcek/v1/{product}/{chip_id}?blSPL={n}&teeSPL={n}&snpSPL={n}&ucodeSPL={n}
```

- `chip_id` — 64-byte hardware identifier read from the guest's attestation report.
- The SVN query parameters are taken from the `TCB_VERSION` field of the same report.
- KDS returns a DER-encoded X.509 certificate. AMD issues it on demand — the private key was provisioned in the chip at manufacture time.

ARK and ASK for a given product line are fetched from:

```
GET https://kdsintf.amd.com/vcek/v1/{product}/cert_chain
```

This service returns the full ARK+ASK chain as a PEM bundle. In this repo `FakeKDS` simulates that by reading from local `testdata/` files.

---

## VLEK — VM Launch Endorsement Key

VLEK is an **alternative signing key** introduced to support multi-tenant environments where the chip's unique hardware identity (CHIP_ID) must stay private.

| | VCEK | VLEK |
|---|---|---|
| Keyholder | AMD ASP (hardware) | Cloud provider's AMD-hosted HSM |
| Identity encoded | Chip serial + TCB | TCB only (no chip serial) |
| Certificate issuer | AMD KDS | AMD (via SEV-SNP Versioned Loaded Endorsement Key infrastructure) |
| Use case | Bare-metal / single-tenant | Multi-tenant / chip-ID privacy required |
| Private key location | Inside the AMD ASP die | Cloud provider HSM, provisioned by AMD |

When a VLEK is active, the ASP signs attestation reports with the VLEK private key instead of the VCEK private key. The attestation report's `SIGNING_KEY` field indicates which was used. The certificate chain still terminates at the AMD ARK.

---

## What Gets Signed and by Whom

```
┌─────────────────────────────────────────────────────────────┐
│  AMD Factory                                                │
│  • Provisions VCEK private key into ASP at manufacture time │
│  • ARK private key signs ASK cert (offline HSM)            │
│  • ASK private key signs VCEK cert (issued via KDS)        │
└─────────────────────────────────────────────────────────────┘
                │
                │ (certificate chain published on KDS)
                ▼
┌─────────────────────────────────────────────────────────────┐
│  AMD ASP (on-chip, at runtime)                             │
│  • VCEK private key signs the 1184-byte attestation report │
│    using ECDSA-P384                                        │
└─────────────────────────────────────────────────────────────┘
                │
                │ (report + sig delivered to verifier)
                ▼
┌─────────────────────────────────────────────────────────────┐
│  Verifier (this service)                                   │
│  • Fetches ARK, ASK, VCEK certs from KDS                   │
│  • Verifies cert chain: ARK self-signs → ASK → VCEK        │
│  • Extracts VCEK public key                                │
│  • Runs ECDSA-P384 verify(report_body, signature, pub_key) │
└─────────────────────────────────────────────────────────────┘
```

### How the Public Key Is Used to Verify the Signature

1. The verifier fetches the VCEK certificate from KDS.
2. It verifies the certificate chain — ASK's public key checks VCEK's signature; ARK's public key checks ASK's signature; ARK is self-signed and trusted by pin.
3. It extracts the **ECDSA public key** from the verified VCEK certificate.
4. It computes `SHA-256` (or `SHA-384` in hardware) over the serialised attestation report body.
5. It calls `ECDSA.Verify(public_key, digest, signature)`.
6. If this passes, the report was provably produced by an ASP holding the private key whose public counterpart AMD certified — i.e., a real AMD chip at the stated TCB level.

In code (`internal/report/verify.go`):

```go
pub, ok := vcek.PublicKey.(*ecdsa.PublicKey)
ecdsa.VerifyASN1(pub, digest[:], sig)
```

---

## How Private Keys Are Used for Decryption Inside SEV-SNP

Private keys in AMD SEV-SNP are used for two distinct purposes:

### 1. Memory Encryption (AES-128 / AES-256)

The ASP generates a unique **VM Encryption Key (VEK)** per VM at launch. This symmetric key is used by the AMD memory controller to transparently encrypt and decrypt all guest RAM via AES in XEX mode. The hypervisor DMA-ing guest memory reads only ciphertext. The key never leaves the ASP.

### 2. Key Derivation for Guest-held Secrets (LAUNCH_SECRET / GET_DERIVED_KEY)

After attestation succeeds, a secret (e.g., a disk-encryption key) can be **sealed** to a VM by wrapping it with a key the ASP will only derive if the TCB and measurement match:

```
┌─────────────────────────────────────────────────────────────┐
│  Secret provisioning (at KMS / relying party)              │
│  1. Guest generates ephemeral EC key pair (pub, priv).     │
│  2. Guest hashes pub_key → puts hash in REPORT_DATA.       │
│  3. Verifier validates attestation report, sees hash.      │
│  4. Verifier wraps secret with pub_key (ECIES / HPKE).     │
│  5. Verifier sends ciphertext to guest.                    │
└─────────────────────────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────┐
│  Inside the guest (confidential VM)                        │
│  6. Guest holds the matching priv_key in memory            │
│     (protected by SEV memory encryption — hypervisor       │
│      cannot read it).                                      │
│  7. Guest decrypts ciphertext with priv_key → secret.      │
└─────────────────────────────────────────────────────────────┘
```

Alternatively, AMD's `SNP_GET_DERIVED_KEY` hypercall lets the ASP derive a deterministic key bound to the VM's measurement and TCB, which the guest can use as a root key without any external KMS interaction.

In this repo, `internal/secret/release.go` models the final gate: the secret is only returned to the caller after all attestation checks pass (`trusted == true`).

---

## Full Production Attestation Flow

```
Guest VM (inside SEV-SNP)           Verifier (this service / KMS)
─────────────────────────           ──────────────────────────────
                                    1. Generate challenge nonce N.
                                    2. Send N to guest.

3. Call SNP_GET_REPORT(N).
   ASP embeds N in REPORT_DATA,
   signs report with VCEK priv key.
4. Return signed report + CHIP_ID
   + TCB_VERSION to guest.
5. Send report to verifier.
                                    6. Extract CHIP_ID + TCB from report.
                                    7. Fetch VCEK cert from AMD KDS
                                       using CHIP_ID + TCB SVNs.
                                    8. Fetch ARK + ASK cert chain from KDS.
                                    9. Verify ARK → ASK → VCEK chain.
                                   10. Verify ECDSA signature on report
                                       using VCEK public key.
                                   11. Verify REPORT_DATA contains N
                                       (replay prevention).
                                   12. Check MEASUREMENT against
                                       allowlist (known-good workloads).
                                   13. Check TCB_VERSION >= minimum
                                       per-component SVN policy.
                                   14. If all checks pass: release secret
                                       (unwrap KMS key, issue JWT, etc.)
                                   15. Send secret/token to guest.

16. Decrypt with ephemeral priv key
    (held only in encrypted guest RAM).
17. Use secret (mount disk, mTLS, etc.)
```

---

## TCB Version Components

The `TCB_VERSION` uint64 encodes four Security Version Numbers (SVNs). A higher SVN means more patches applied. Policy rejects reports where any component is below the minimum:

| Bits | Component | Description |
|---|---|---|
| 7:0 | `BootloaderSVN` | BIOS/UEFI bootloader firmware |
| 15:8 | `TEESVN` | AMD TEE firmware (PSP) |
| 47:16 | *(reserved)* | — |
| 55:48 | `SNPSVN` | AMD SEV-SNP firmware |
| 63:56 | `MicrocodeSVN` | CPU microcode |

See `internal/tcb/tcb.go` for parsing and component-wise comparison.

---

## Project Structure

```
cmd/main.go                 — end-to-end demo: fetch certs, verify chain,
                              verify report, evaluate policy, release secret
internal/certs/
  chain.go                  — ARK→ASK→VCEK X.509 chain verification
  fakekds.go                — local file stand-in for AMD KDS HTTP calls
internal/report/
  report.go                 — AttestationReport type + nonce check
  verify.go                 — ECDSA signature verification using VCEK public key
internal/tcb/tcb.go         — TCB version parsing + component-wise SVN check
internal/policy/policy.go   — measurement allowlist + minimum TCB policy
internal/secret/release.go  — secret release gated on attestation result
internal/utils/helper.go    — PEM → x509.Certificate parser
testdata/                   — pre-generated certs and report for offline demo
```

## Running the Demo

```bash
go run ./cmd/main.go
```

Expected output:

```
certificate chain verified
report signature valid
secret released: super-secret-key-material
Finished Validation
```
