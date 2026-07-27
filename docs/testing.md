# Stomper Testing Guide

**Project:** Stomper – Rust Network Intrusion Detection System (IDS)  
**Course:** CSE 499 – Senior Software Engineering Project  
**Team:** Team 05  
**Version:** 1.0  
**Sprint:** Sprint 2

---

# 1. Purpose

This document provides the procedures for building, running, and testing the Stomper Network Intrusion Detection System (IDS). It serves as the primary testing reference for all team members throughout development.

The objectives of testing are to:

- Verify packet capture functionality.
- Validate packet parsing.
- Verify attack detection algorithms.
- Ensure alerts are generated correctly.
- Identify defects before integration.

---

# 2. Scope

This document covers testing for the following modules:

| Module | Description |
|---------|-------------|
| Packet Capture | Captures live packets from a network interface. |
| Packet Parser | Parses Ethernet, IPv4, TCP, and UDP packets. |
| Detection Engine | Detects suspicious network behavior. |
| Alert Module | Displays alerts for detected attacks. |

---

# 3. Development Environment

| Item | Version |
|------|---------|
| Operating System | Windows 11 / macOS / Linux |
| Rust | 1.97.0 or later |
| Cargo | Latest Stable |
| pcap crate | 1.3.0 |
| Git | Latest |
| VS Code | Recommended |

---

# 4. Project Setup

Clone the repository.

```bash
git clone <repository-url>
cd Stomper
```

Install dependencies.

```bash
cargo build
```

Run the project.

```bash
cargo run
```

---

# 5. Testing Strategy

Testing is divided into four phases.

## Phase 1 – Build Verification

Objective:

Ensure the project compiles successfully.

Command:

```bash
cargo build
```

Expected Result:

- Project builds without errors.
- No warnings affecting functionality.

---

## Phase 2 – Packet Capture Testing

Objective:

Verify packets are captured from the selected network interface.

Expected Results:

- Capture starts successfully.
- Packets are received.
- No unexpected crashes occur.

---

## Phase 3 – Packet Parsing Testing

Objective:

Verify captured packets are parsed correctly.

Expected Results:

- Ethernet headers parsed.
- IPv4 packets identified.
- TCP packets parsed.
- UDP packets parsed.
- Invalid packets handled gracefully.

---

## Phase 4 – Detection Testing

Objective:

Verify attacks are detected correctly.

Expected Results:

- Port scans detected.
- SYN flood attacks detected.
- Normal traffic ignored.

---

# 6. Console Alert Testing

Objective:

Verify alerts are displayed correctly.

Expected Result:

Alerts should contain:

- Timestamp
- Attack Type
- Source IP
- Destination IP
- Severity Level

Example:

```
[2026-07-23 08:35:14]

ALERT: Port Scan Detected

Source:
192.168.1.50

Destination:
192.168.1.1

Severity:
Medium
```

---

# 7. Regression Testing

Regression testing should be performed after:

- New feature implementation
- Bug fixes
- Module integration
- Dependency updates

Verify:

- Build succeeds
- Packet capture works
- Parser still functions
- Detection accuracy maintained
- Alerts generated correctly

---

# 8. Known Issues

Record known issues discovered during testing.

| ID | Description | Status |
|----|-------------|--------|
| ISSUE-001 | Windows build reports timestamp type mismatch (`expected i64, found i32`) during packet parsing integration. | Under Investigation |

---

# 9. Test Reports

Each completed test should record:

- Date
- Tester
- Feature Tested
- Result
- Notes

Example:

| Date | Tester | Test | Result | Notes |
|------|--------|------|--------|------|
| YYYY-MM-DD | Team Member | Packet Capture | Pass | Successfully captured packets |

---

# 10. Future Testing

Future testing will include:

- Performance testing
- Stress testing
- Large packet captures
- Multiple simultaneous attacks
- Cross-platform testing
- End-to-end integration testing

---

# 11. References

- Rust Programming Language
- Cargo Documentation
- pcap Crate Documentation
- Project Design Documents
- Sprint Planning Documents

---

# Revision History

| Version | Date | Author | Description |
|----------|------|--------|-------------|
| 1.0 | July 2026 | Liezl Gonzaga Lizardo | Initial testing guide created during Sprint 2. |