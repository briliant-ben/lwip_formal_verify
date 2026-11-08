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

- `LWIP_FORMAL_VERIFICATION_REPORT.md`: full report (theorems, defects, results).
- `lwip_formal_verification_fixes.patch`: defensive fixes against the baseline commit.
- `lwip_formal_verification_suite.c`: standalone 30-theorem suite.
- `lwip_upstream_integration_test.c`: harness linked against the patched upstream sources.
- `port/include/`: Linux build port (`lwipopts.h`, `arch/`).
- `Reference/`: original Phase 1-4 suite.
