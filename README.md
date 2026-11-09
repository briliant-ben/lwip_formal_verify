# lwIP Formal Verification

Formal verification and defensive patching of lwIP 2.2.2d using the Anthropic x Theorem three-theorem paradigm
(A: ASan+UBSan crash-freedom, B: sanitizer vs `-O2` trace equivalence, C: plain `-O2` crash-freedom).

Baseline: https://github.com/lwip-tcpip/lwip.git at commit `315de84e79245a0c0f2ae4329ca6602b9f42fb1c`
(`STABLE-2_2_1_RELEASE-63-g315de84e`).

## Reproduce

```sh
git clone https://github.com/lwip-tcpip/lwip.git lwip
git -C lwip checkout 315de84e79245a0c0f2ae4329ca6602b9f42fb1c
git -C lwip apply ../lwip_formal_verification_fixes.patch
make verify
```

## Contents

- `LWIP_FORMAL_VERIFICATION_REPORT.md`: full verification and audit report (40 theorems, 40 patched modules, results).
- `lwip_formal_verification_fixes.patch`: unified defensive patch across 40 upstream files (+353 / -96).
- `lwip_formal_verification_suite.c`: standalone 40-theorem formal verification suite across 8 phases.
- `lwip_upstream_integration_test.c`: real upstream integration harness linking >60 lwIP modules.
- `port/include/`: Linux build port (`lwipopts.h`, `arch/`).
- `Reference/`: original Phase 1-4 suite.
