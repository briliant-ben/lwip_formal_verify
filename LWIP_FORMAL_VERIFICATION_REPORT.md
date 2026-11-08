# lwIP Full-Stack Formal Verification & Security Audit Report

## 1. Verification Baseline

| Item | Value |
|---|---|
| Repository | https://github.com/lwip-tcpip/lwip.git |
| Version | **lwIP 2.2.2d** |
| Git describe | `STABLE-2_2_1_RELEASE-63-g315de84e` |
| Commit | `315de84e79245a0c0f2ae4329ca6602b9f42fb1c` (2026-11-04, "netbiosns: fix netbiosns_name_decode reading oob of the receive buffer") |
| Patch | `lwip_formal_verification_fixes.patch` (26 files, +285/-51) |

## 2. Methodology (Anthropic x Theorem three-theorem paradigm)

- **Theorem A**: zero crashes and zero reports under ASan + UBSan (`-O1 -fsanitize=address,undefined`).
- **Theorem B**: the sanitizer build and the `-O2` build produce identical I/O traces (`diff -u` shows zero differences).
- **Theorem C**: the plain `-O2` binary runs without crashing and exits with code 0.

Two verification paths:
1. `lwip_formal_verification_suite.c`: a standalone, self-contained suite of 30 theorems (models plus exhaustive enumeration).
2. `lwip_upstream_integration_test.c`: links directly against the patched upstream lwIP sources (about 90 `.c` files) and feeds them counterexample inputs.

Reproduce with `make verify` (uses the Linux port headers in `port/include/`).

## 3. Theorem Inventory (Theorems 1-30)

| Phase | Theorems | Modules |
|---|---|---|
| 1 | 1-3 | pbuf, dns |
| 2 | 4-10 | ip4, ip4_frag, ip6, ip6_frag, nd6, tcp_in, udp |
| 3 | 11-15 | dhcp, etharp/ethernet, tcp_out, icmp6/mld6, icmp |
| 4 | 16-20 | dhcp6, mqtt, mdns, igmp/inet_chksum, mem/sntp |
| 5 | 21-26 | tcp/raw/acd, ip4_addr/ip6_addr, lowpan6 (+BLE), zepif, vj, slipif/bridgeif |
| 6 | 27-30 | pppoe/pppol2tp, tftp, netbiosns, snmp/http_client |

## 4. Defects Found and Fixed

### 4.1 Phases 1-4 (still unpatched in upstream 315de84e)

| File | Function | Defect type |
|---|---|---|
| dns.c | dns_compare_name | 1-byte OOB read, prefix-truncation false positive, literal `.` inside a label |
| ip4.c | ip4_input | Dereference before length check (OOB read on frames < 4 bytes) |
| ip4_frag.c | ip4_reass | Out-of-order MF=0 assertion crash; 16-bit `tot_len` wrap |
| ip6.c | ip6_input | 1-byte OOB read in extension header / HBH / DestOpts TLV parsing |
| ip6_frag.c | ip6_reass | Header budget (IP6_HLEN / unfragmentable headers) not reserved; remote abort |
| nd6.c | nd6_input | 6-byte OOB read when `lladdr_opt->length == 0` |
| dhcp.c | dhcp_parse_reply | Cross-field OOB read with option overload (sname/file) |
| etharp.c | etharp_input | OOB read on ARP frames shorter than 28 bytes |
| icmp.c | icmp_send_response | 8-byte OOB read |
| dhcp6.c | dhcp6_parse_reply | Missing `offset > offset_max` check; `u16_t` wrap |
| mqtt.c | mqtt_message_received | 1-byte OOB write (`topic[topic_len] = 0`) when `after_topic == length` |
| mdns_domain.c | mdns_readname_loop | 0xFFFF offset wrap |
| igmp.c | igmp_input | Checksum omitted for split pbuf chains |

### 4.2 Phases 5-6 (newly discovered)

| File | Defect |
|---|---|
| lowpan6.c / lowpan6_ble.c | FRAGN not checked for overlap with the preceding fragment; chained pbuf overwrites `reass->next`; 11-bit datagram_size truncation; empty pbuf in `rfc7668_input` |
| zepif.c | `tot_len - 2` underflow when `zep->len < 2`; `pbuf_realloc` assertion crash |
| ppp/vj.c | 19-byte read before the length check; `vj_compress_init` leaves `rstate[]` uninitialized |
| slipif.c / bridgeif.c | `q = p` creates a `p->next = p` infinite loop; off-by-one in `recved <= SLIP_MAX_SIZE`; bridgeif does not check the 14-byte header |
| ppp/pppoe.c | Read before check under `PPPOE_TERM_UNKNOWN_SESSIONS`; undefined `ETHER_ADDR_LEN`; trailing padding not trimmed; 16-bit tag offset overflow |
| tftp.c | OOB read when `p->len < 2` or `< 4` |
| netbiosns.c | 1-byte OOB read for odd `name_enc_len`; missing NUL terminator; `-1` return value ignored |
| snmp_msg.c / http_client.c | `error_index` check applied to the wrong variable; header search runs past `\r\n\r\n`; `tot_len` overflow in `pbuf_cat` |
| ip4_addr.c | `ip4addr_aton` accepts u32 overflow in decimal/octal/hex parts (e.g. `4294967296`) |
| ip6_addr.c | `ip6addr_aton` accepts multiple `::`, silently truncates blocks longer than 4 hex digits, and underflows `zero_blocks` on excess colons |

> The last two were found by the integration test running against the real upstream code.

## 5. Results

- 30-theorem suite: all PASS in both the sanitizer and `-O2` builds; `diff -u` shows zero differences.
- Upstream integration test: all 9 counterexample groups PASS, no ASan/UBSan reports, `diff -u` shows zero differences.
- 54+ upstream modules compile with `-Wall -Wextra -Werror` and zero warnings.

## 6. Known Limitations

- The integration test is a regression/counterexample check for identified defects, not a complete proof of the whole code base. The other 21 theorems are verified on standalone models.
- `MEM_ALIGNMENT` is set to 8 to avoid UBSan false positives from under-aligned `struct pbuf` on 64-bit hosts (a port configuration issue, not an lwIP defect).
- Suggested follow-ups: fuzz each `*_input` entry point with libFuzzer/AFL++ and submit the patch upstream.
