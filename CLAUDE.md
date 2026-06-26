# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Coding Style

New code must match the style of the surrounding open5gs source: C99/gnu89 with `ogs_` prefixed types and APIs, `OGS_` prefixed macros, snake_case identifiers, pool-allocated structs managed via `OGS_POOL`/`ogs_pool_alloc`, and linked lists via `ogs_list_t`. Follow the existing NF file layout (see NF internal pattern below). Do not introduce new patterns, helper abstractions, or type aliases that do not already exist in the codebase.

## Code Logging & Comments

Log messages and code comments must be professional and describe the event or condition, not the implementation progress. Never use stage/step/phase markers like `/* Step 1 */`, `ogs_log("Phase 2: ...")`, or `// TODO: stage 3` to narrate what the code is doing. Each message stands alone and reads as production output, not a development breadcrumb.

## File Access Scope

Only read files inside this repository (`/home/long_le/ws/TSN-scheduler/open5gs/`). Do not read files outside this directory, except for Claude's own internal config files (e.g. `~/.claude/`).

## Build

This project uses Meson + Ninja. All builds run in Docker (see parent repo constraints — never run meson/ninja natively on the host).

```bash
meson setup build --prefix=$(pwd)/install
ninja -C build
```

Key meson options: `--buildtype=debug`, `-Dfuzzing=false` (default).

Static analysis targets (after setup):
```bash
meson compile -C build analyze-clang-tidy
meson compile -C build analyze-cppcheck
```

## Tests

Tests require a MongoDB instance and a TUN device (`ogstun`, 10.45.0.1/16). CI sets these up via `.github/workflows/meson-ci.yml`.

```bash
meson test -C build -v                        # all tests
meson test -C build -v crypt unit             # specific suites
./build/tests/registration/registration       # 5G Core scenario
./build/tests/attach/attach                   # EPC scenario
```

Test suites under `tests/`: `core/`, `crypt/`, `sctp/`, `unit/`, `registration/`, `attach/`, `handover/`, `slice/`, `non3gpp/`, `volte/`, `vonr/`, `csfb/`, `transfer/`.

## Architecture

### Library layer (`lib/`)

| Library | Purpose |
|---------|---------|
| `core/` | Memory pools, event loops (ogs-event), timers, logging, YAML config |
| `app/` | Application framework — config loading, NF lifecycle |
| `sbi/` | HTTP/2 service-based interface (SBI/NRF registration, discovery) |
| `ngap/` | NG Application Protocol (N2 — AMF↔gNB) |
| `s1ap/` | S1 Application Protocol (MME↔eNB, EPC) |
| `nas/5gs/` | 5G NAS (N1 — AMF↔UE) |
| `nas/eps/` | EPS NAS (LTE — MME↔UE) |
| `pfcp/` | Packet Forwarding Control Protocol (N4 — SMF↔UPF) |
| `gtp/` | GTPv1/v2 tunneling |
| `diameter/` | Diameter protocol (EPC Cx/Gx/Rx/S6a) |
| `dbi/` | MongoDB interface (subscriber/session data) |
| `crypt/` | AES, HMAC, KDF, integrity/ciphering |
| `sctp/` | SCTP socket abstraction |
| `tun/` | TUN device management |
| `metrics/` | Prometheus metrics |
| `asn1c/` | ASN.1 generated code (do not hand-edit) |
| `ipfw/` | IP packet filter rules |

### Network Function layer (`src/`)

**5G Core (SA):**
- `amf/` — Access & Mobility Management (N1/N2 termination, registration, paging)
- `smf/` — Session Management (PDU sessions, PFCP toward UPF, PCF interaction)
- `upf/` — User Plane (GTP tunneling, packet routing, TUN interface)
- `pcf/` — Policy Control (PCC rules, QoS, TSC/TSN policy)
- `nrf/` — Network Repository (NF registration & discovery)
- `ausf/` — Authentication Server (5G-AKA, EAP-AKA')
- `udm/` — Unified Data Management (subscriber profiles)
- `udr/` — Unified Data Repository (raw data storage)
- `nssf/` — Network Slice Selection
- `bsf/` — Binding Support Function (PCF binding, MAC-based lookup for Ethernet PDUs)
- `scp/` — Service Communication Proxy
- `sepp/` — Security Edge Protection (inter-PLMN roaming)

**LTE/EPC:**
- `mme/` — Mobility Management (S1AP, EPS NAS, S11 toward SGW)
- `hss/` — Home Subscriber Server (Diameter S6a)
- `sgwc/` / `sgwu/` — Serving Gateway (control/user plane split)
- `pgwc=smf` / `pgwu=upf` — PGW reused from 5G NFs
- `pcrf/` — Policy & Charging Rules (Diameter Gx/Rx)

### NF internal pattern

Every NF follows the same file layout:
- `init.c` — startup/shutdown, library init order
- `context.c/h` — singleton context struct, pool allocation, linked lists of sessions/bearers
- `event.c/h` — event type enum + `ogs_event_t` allocation helpers
- `*-sm.c` — finite state machine (one per interface, driven by `ogs_fsm_dispatch`)
- `*-handler.c` — message handler dispatch (called from state machine)
- `*-build.c` — outgoing message construction
- `*-path.c` — cross-interface routing (e.g., SMF sending PFCP after receiving NAS)
- `timer.c/h` — retransmission / guard timers
- `metrics.c/h` — Prometheus counters/gauges

### Event loop

Each NF runs a single `ogs_app_run()` loop. Events are queued via `ogs_queue_push()` and dispatched by the FSM. All I/O (SCTP, UDP/GTP, HTTP/2) uses libevent under `lib/core/`.

### Fork changes relative to upstream open5gs (branch `review/tsn-dev`)

81 commits, ~11 600 insertions / ~2 700 deletions across 179 files.

#### 1. TSN / Ethernet feature set (9 commits — the primary research contribution)

| Commit | What changed |
|--------|-------------|
| `smf, pcf, pfcp, nas, upf` | TSC/TSN NGAP conformance + Ethernet bearer steering: SMF carries TSC Assistance Information through PFCP to the UPF; NGAP path carries TSC parameters toward the RAN |
| `pcf, smf, pfcp, dbi, sbi` | PCF→AF relay (Npcf_PolicyAuthorization N5 leg); PMIC-only N5 flow; DNN exact-match in policy lookup |
| `SMF — TSC context & NGAP` | `smf_tsn_*` context fields; SMF encodes TSC parameters in NGAP PDU Session Resource Setup |
| `UPF — TSN bridge, NW-TT` | UPF manages a TSN bridge port (NW-TT), gates traffic per TSN schedule, handles Ethernet-type PDU sessions |
| `BSF — MAC-based PCF binding` | BSF indexes PCF bindings by Ethernet source MAC (in addition to IP); enables bridge-port-to-PCF lookup for TSN steering |
| `PCF & misc` | PCF policy evaluation extended for TSN QoS descriptors; misc SBI model additions |
| `Shared libs — Ethernet filters & PFCP refactor` | `lib/sbi/` adds Ethernet packet filter IE helpers; `lib/pfcp/` refactored for Ethernet PDR/FAR |
| `pfcp, sbi, smf: replace eth\| sentinel` | Replaced the `eth|` string-sentinel hack with spec-compliant PFCP Ethernet PDR IEs (TS 29.244) |
| `clangd: in-Docker meson build config` | `.clangd` pointed at the in-container build tree for IDE integration |

**New/extended test coverage:** `tests/af/` (AF scenario tests, 501 lines added to `vonr/af-test.c`), `tests/unit/eth-flow-test.c` (Ethernet flow filter unit tests).

#### 2. Security hardening (≈50 commits — upstreamed-candidate fixes)

All defensive; no behavioral changes to the happy path.

**Input validation / bounds checking:**
- `amf`: 5GS mobile identity length, NAS PDU length, AM data size, DNN info count, duplicate RAN_UE_NGAP_ID, SM context update, NAS container type mismatch, malformed `namf` handler inputs
- `mme`: NAS PDU length, path-switch ownership, TAU BCS presence mask, mobility procedure sequencing
- `smf`: PDU session identity range, empty SUPI hash access, QoS flow lookup in PFCP modification, PCC rule handling, HR roaming SBI, HsmfUpdateData, NGAP QFI mismatch, UE-requested QoS modification
- `pcf`: SM Policy IP address fields, malformed SBI inputs, `qosReference` profile support (AF-initiated)
- `sbi`: timestamp string length, multipart header fields, discovery parameters, callback URI path component, HTTP/2 stream allocation failure, outbound xact cancel on stream close
- `pfcp`: Outer Header Creation IE length, packet bounds before PDR matching, SDF filter loop bounds
- `nas`: malformed QoS rules and flow descriptions (two separate passes)
- `udm`: UECM/UEAU edge cases
- `dbi`: malformed subscriber identifiers
- `ipfw`: protocol name lookup failure (abort avoided)
- `core`: invalid fixed-width TLV integer lengths; rehashing keys when clearing hash tables (use-after-free fix)
- `crypt`: replace legacy base64 helpers with size-aware APIs

**Context lifecycle / crash fixes:**
- `amf`: stale RAN-UE in NRF discovery response, send `UEContextReleaseCommand` for held NG context, remove unregistered UE on gNB disconnect, keep old RAN context until release command, NRF discovery failure refactor, abort on invalid SM context update
- `mme`: send `UEContextReleaseCommand` for held S1 context, keep old RAN context until release command, T3396 back-off timer on PDN connectivity reject
- `smf`: missing SBI stream after PFCP deletion, unify IMSI/SUPI UE indexes
- `sgwc`: missing GTP transactions in Sxa response handlers
- `core,amf,mme`: avoid stale context clearing active hash entries
- `ngap,s1ap`: preserve UE security capabilities across path switch

#### 3. NRF / SBI robustness (7 commits)

- `nrf`: reject non-positive `heartBeatTimer`; defer PLMN list update until PATCH validation; reject overflowing NFProfile lists
- `nrf,sbi`: harden NF instance allocation and NFM routes
- `sbi`: cancel pending outbound xacts on stream close; handle NRF subscription pool exhaustion; update NFProfile incrementally
- `NRF`: fix delayed inter-PLMN discovery response after stream close

#### 4. Observability / info API extensions (5 commits)

- `amf`: `/ue-info` now includes `mm_state`; `/gnb-info` includes gNB node name
- `mme`: `/ue-info` includes `mm_state` and last-known eNB-ID for ECM-IDLE UEs; `/enb-info` includes eNB node name
- `mme/smf`: expose UE location timestamp in info dumps

#### 5. Misc / docs (3 commits)

- Fix PATH SWITCH REQUEST ACKNOWLEDGE IE order (NGAP encoding bug)
- Add `.gitignore` entry for re-merge artifacts
- Add `SECURITY.md` (policy + scope section)

## Configuration

YAML configs under `configs/`. Each NF reads its own section; `ogs_app_config_init()` parses it. The `sbi.server`/`sbi.client` blocks control HTTP/2 addresses; `freeDiameter` blocks control Diameter peer connections.

## WebUI

`webui/` is a separate Node/React app (Express backend, React+Redux frontend, MongoDB via Mongoose). Run independently with `npm run dev` inside `webui/`. Not part of the meson build.
