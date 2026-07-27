# Parser Test Plan

**Project:** Stomper – Rust Network Intrusion Detection System (IDS)  
**Course:** CSE 499 – Senior Software Engineering Project  
**Team:** Team 05  
**Sprint:** Sprint 2  
**Version:** 1.0

---

# 1. Purpose

This document defines the test cases used to verify the functionality of the Packet Parser module.

The parser is responsible for converting captured network packets into structured data that can be processed by the Detection Engine.

---

# 2. Objectives

The objectives of parser testing are to:

- Verify Ethernet frame parsing.
- Verify IPv4 packet parsing.
- Verify TCP header parsing.
- Verify UDP header parsing.
- Verify graceful handling of malformed packets.
- Verify unsupported protocols are handled safely.

---

# 3. Test Environment

| Item | Value |
|------|-------|
| Operating System | Windows 11 / macOS / Linux |
| Rust | 1.97.0 or later |
| Cargo | Stable |
| Packet Source | Live Network Traffic |
| Parser Module | `capture/parser.rs` |

---

# 4. Test Cases

## PARSER-001 – Parse Ethernet Frame

**Objective**

Verify that the parser successfully identifies an Ethernet frame.

**Preconditions**

- Packet capture is running.
- Ethernet traffic is available.

**Steps**

1. Start packet capture.
2. Capture an Ethernet frame.
3. Pass the packet to the parser.

**Expected Result**

- Ethernet header is parsed successfully.
- Source MAC address is extracted.
- Destination MAC address is extracted.
- EtherType is identified.

---

## PARSER-002 – Parse IPv4 Packet

**Objective**

Verify IPv4 packets are parsed correctly.

**Steps**

1. Capture an IPv4 packet.
2. Parse the packet.

**Expected Result**

- Source IP detected.
- Destination IP detected.
- Protocol identified.
- Packet accepted.

---

## PARSER-003 – Parse TCP Packet

**Objective**

Verify TCP headers are parsed correctly.

**Steps**

1. Capture TCP traffic.
2. Parse the packet.

**Expected Result**

- Source Port identified.
- Destination Port identified.
- TCP flags extracted.
- Packet accepted.

---

## PARSER-004 – Parse UDP Packet

**Objective**

Verify UDP packets are parsed correctly.

**Steps**

1. Capture UDP traffic.
2. Parse the packet.

**Expected Result**

- Source Port identified.
- Destination Port identified.
- UDP payload recognized.

---

## PARSER-005 – Invalid Packet

**Objective**

Verify malformed packets are handled safely.

**Steps**

1. Send an incomplete packet.
2. Parse the packet.

**Expected Result**

- Parser returns an error.
- Application continues running.
- No crash occurs.

---

## PARSER-006 – Empty Packet

**Objective**

Verify empty packets do not crash the parser.

**Steps**

1. Pass an empty packet.

**Expected Result**

- Error returned.
- No panic.
- No crash.

---

## PARSER-007 – Unsupported Protocol

**Objective**

Verify unsupported protocols are handled correctly.

**Steps**

1. Capture an unsupported protocol.
2. Parse the packet.

**Expected Result**

- Packet ignored or reported.
- Application continues running.

---

## PARSER-008 – Truncated Packet

**Objective**

Verify truncated packets are handled safely.

**Steps**

1. Capture or simulate a truncated packet.
2. Parse the packet.

**Expected Result**

- Parser detects incomplete data.
- Appropriate error returned.
- No application crash.

---

# 5. Acceptance Criteria

The parser is considered successful when:

- All supported packet types are parsed correctly.
- Invalid packets are handled gracefully.
- Unsupported protocols do not crash the application.
- No memory errors or application crashes occur.
- Parsed packet information is accurate.

---

# 6. Test Execution Log

| Test ID | Tester | Date | Result | Notes |
|----------|--------|------|--------|-------|
| PARSER-001 | | | Pass / Fail | |
| PARSER-002 | | | Pass / Fail | |
| PARSER-003 | | | Pass / Fail | |
| PARSER-004 | | | Pass / Fail | |
| PARSER-005 | | | Pass / Fail | |
| PARSER-006 | | | Pass / Fail | |
| PARSER-007 | | | Pass / Fail | |
| PARSER-008 | | | Pass / Fail | |

---

# 7. Risks

Potential issues that may affect parser testing include:

- Platform-specific packet capture behavior.
- Malformed or incomplete packets.
- Differences between operating systems.
- Network interface permissions.
- Build compatibility issues.

---

# 8. Recommendations

- Execute parser tests on Windows, macOS, and Linux when possible.
- Include both live traffic and sample packet captures.
- Repeat tests after significant parser changes.
- Perform regression testing before each sprint review.

---

# Revision History

| Version | Date | Author | Description |
|----------|------|--------|-------------|
| 1.0 | July 2026 | Liezl Gonzaga Lizardo | Initial parser test plan created for Sprint 2. |