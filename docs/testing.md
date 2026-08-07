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

# Stomper Testing Guide

**Project:** Stomper – Rust Network Intrusion Detection System (IDS)  
**Course:** CSE 499 – Senior Software Engineering Project  
**Team:** Team 05  
**Version:** 2.0  
**Sprint:** Sprint 4

---

# 1. Purpose

This document provides the procedures for building, running, and testing the Stomper Network Intrusion Detection System (IDS). It serves as the primary testing reference for all team members throughout development.

The objectives of testing are to:

- Verify packet capture functionality.
- Validate packet parsing.
- Verify attack detection algorithms.
- Ensure alerts are generated correctly.
- Verify SQLite database integration.
- Verify REST API functionality.
- Identify defects before integration and release.

---

# 2. Scope

This document covers testing for the following modules:

| Module | Description |
|---------|-------------|
| Packet Capture | Captures live packets from a network interface. |
| Packet Parser | Parses Ethernet, IPv4, TCP, UDP, and ICMP packets. |
| Detection Engine | Detects suspicious network behavior including Port Scan and SYN Flood attacks. |
| Alert Module | Creates alerts and displays detected attacks in the console. |
| SQLite Database | Stores alerts and provides historical alert retrieval. |
| REST API | Provides runtime status and alert information for dashboard integration. |

---

# 3. Development Environment

| Item | Version |
|------|---------|
| Operating System | Windows 11 / Linux |
| Rust | 1.97.0 or later |
| Cargo | Latest Stable |
| pcap crate | 1.3.0 |
| SQLite | 3.x |
| SQLx | 0.9 |
| Npcap (Windows) | Latest |
| libpcap (Linux) | Latest |
| Git | Latest |
| VS Code | Recommended |
| DBeaver | Latest |

---

# 4. Project Setup

Clone the repository.

```bash
git clone <repository-url>
cd Stomper
```

Build the project.

```bash
cargo build
```

Run all unit tests.

```bash
cargo test
```

Run the application.

```bash
cargo run
```

---

# 5. Testing Strategy

Testing is divided into multiple phases.

## Phase 1 – Build Verification

### Objective

Ensure the project compiles successfully.

### Command

```bash
cargo build
```

### Expected Results

- Project builds successfully.
- No compilation errors.
- Required dependencies are resolved correctly.

---

## Phase 2 – Packet Capture Testing

### Objective

Verify packets are captured from the selected network interface.

### Expected Results

- Capture starts successfully.
- Packets are received.
- Runtime statistics update correctly.
- No unexpected crashes occur.

---

## Phase 3 – Packet Parsing Testing

### Objective

Verify captured packets are parsed correctly.

### Expected Results

- Ethernet headers parsed.
- IPv4 packets parsed.
- TCP packets parsed.
- UDP packets parsed.
- ICMP packets parsed.
- Invalid packets handled gracefully.

---

## Phase 4 – Detection Testing

### Objective

Verify attack detection algorithms.

### Expected Results

- Port Scan detected.
- SYN Flood detected.
- Normal traffic ignored.
- No false positives during ordinary browsing.

---

## Phase 5 – Integration Testing

### Objective

Verify communication between all project components.

### Expected Results

- Packet Capture → Detection Engine
- Detection Engine → Alert Manager
- Alert Manager → SQLite Database
- REST API → SQLite Database
- REST API → Dashboard

---

# 6. Database Testing

## Objective

Verify alerts are stored correctly in the SQLite database.

### Expected Results

- SQLite database created successfully.
- Alert records inserted successfully.
- Stored alerts retrieved successfully.
- Database remains consistent after multiple inserts.

### Verification Steps

1. Open the database using DBeaver.
2. Verify the `alerts` table exists.
3. Confirm alert records are stored correctly.
4. Verify timestamps, severity levels, and IP addresses.

---

# 7. REST API Testing

## Objective

Verify runtime information is exposed through the REST API.

### Endpoint

```
GET /api/status
```

### Expected Result

Example:

```json
{
  "healthy": true,
  "database": "stomper.db",
  "packets_captured": 2172,
  "alerts_generated": 0
}
```

Verify:

- API is reachable.
- JSON response is valid.
- Runtime statistics update correctly.

---

# 8. Console Alert Testing

## Objective

Verify alerts are displayed correctly.

### Expected Result

Alerts should include:

- Timestamp
- Attack Type
- Source IP
- Destination IP
- Severity Level

Example

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

# 9. Regression Testing

Regression testing should be performed after:

- New feature implementation
- Bug fixes
- Module integration
- Dependency updates

Verify:

- Build succeeds
- Unit tests pass
- Packet capture works
- Packet parser functions correctly
- Detection accuracy maintained
- Alerts generated correctly
- SQLite integration remains functional
- REST API remains operational

---

# 10. Known Issues

| ID | Description | Status |
|----|-------------|--------|
| ISSUE-001 | Windows may automatically select the WAN Miniport adapter instead of the active Wi-Fi or Ethernet adapter, resulting in zero captured packets. | Documented |
| ISSUE-002 | High traffic may cause packet drops when the packet queue reaches capacity. | Monitoring |

## Platform Compatibility Testing

Testing was performed on both Windows and Linux systems.

### Windows Observation

During testing on Windows, the application initially selected the **WAN Miniport (Network Monitor)** interface instead of the active wireless adapter. Although the application started successfully and the REST API reported a healthy status, packet capture remained at zero because the selected interface was not receiving normal network traffic.

After manually selecting the active wireless adapter, packet capture operated correctly.

Observed runtime statistics:

| Metric | Result |
|---------|--------|
| Packets Captured | 2,172+ |
| Bytes Captured | 1.7 MB+ |
| Packet Rate | ~48 packets/sec |
| Parse Errors | 0 |
| Alerts Generated | 0 |

### Root Cause

The current implementation automatically selects the first non-loopback interface. On Windows systems, this may correspond to a virtual WAN Miniport adapter rather than the active Ethernet or Wi-Fi adapter.

### Recommendation

A future enhancement may allow users to explicitly choose the desired network interface through:

- Interactive interface selection
- Command-line arguments
- Configuration file support

This approach would improve portability across Windows, Linux, and other supported operating systems.

> **Note:** This observation was documented during testing only. No source code modifications were committed because the workaround was specific to Windows hardware and would not provide a cross-platform solution.

---

---

# 11. Platform Compatibility Testing

Platform compatibility testing was performed on both **Windows** and **Linux** environments to verify that Stomper behaves consistently across operating systems.

## Windows Testing

### Test Environment

| Item | Value |
|------|-------|
| Operating System | Windows 11 |
| Packet Capture Library | Npcap |
| Database | SQLite |
| Database Viewer | DBeaver |
| API | REST API (`/api/status`) |

### Initial Observation

During testing, the application automatically selected the **first non-loopback network interface**, which was:

```text
WAN Miniport (Network Monitor)
```

Although the application started successfully and the REST API reported a healthy status, no network packets were captured.

Example API response:

```json
{
  "healthy": true,
  "interface": "\\Device\\NPF_{2F18D86A-E8E8-4B4B-B245-E4AE21A800CA}",
  "database": "stomper.db",
  "packets_captured": 0,
  "alerts_generated": 0
}
```

### Root Cause

The current implementation automatically selects the first available non-loopback interface.

On Windows systems, this interface may be a **WAN Miniport** instead of the active Ethernet or Wi-Fi adapter, resulting in zero captured packets.

### Temporary Windows Testing Workaround

To verify packet capture functionality during local Windows testing, the active wireless adapter was selected manually by modifying the interface selection logic.

Example:

```rust
let Some(device) = devices
    .iter()
    .find(|d| {
        d.desc
            .as_deref()
            .map(|desc| {
                desc.contains("Wireless")
                    || desc.contains("Wi-Fi")
                    || desc.contains("Intel")
            })
            .unwrap_or(false)
    })
    .or(devices.first())
else {
    eprintln!("No network interfaces found");
    return Ok(());
};
```

> **Note**
>
> The adapter description may differ between computers.
> Examples include:
>
> - Intel(R) Dual Band Wireless-AC 3165
> - Intel(R) Wi-Fi 6 AX200
> - Intel(R) Ethernet Controller
>
> The search string should be adjusted to match the active network adapter on the local Windows system.

### Test Results

After selecting the active wireless adapter, packet capture functioned correctly.

Runtime statistics:

| Metric | Result |
|---------|-------:|
| Application Health | Healthy |
| Packets Captured | 2,172+ |
| Bytes Captured | 1,729,015+ |
| Packet Rate | ~48 packets/sec |
| Parse Errors | 0 |
| Alerts Generated | 0 |

Example API response:

```json
{
  "healthy": true,
  "interface": "\\Device\\NPF_{3E0FD2EE-5E22-4FEF-A653-179F3FDEFD66}",
  "database": "stomper.db",
  "started_at": "2026-08-07T00:52:23.154389500Z",
  "uptime_seconds": 45.02,
  "packets_captured": 2172,
  "bytes_captured": 1729015,
  "parse_errors": 0,
  "packets_dropped_queue_full": 901,
  "alerts_generated": 0,
  "packets_per_second": 48.24
}
```

### Observation

The packet capture engine, parser, REST API, and SQLite integration all functioned correctly once the active network interface was selected.

The issue was related only to automatic interface selection on Windows and did not affect the Linux development environment.

### Recommendation

No source code changes were committed because the workaround is specific to Windows hardware.

For future development, a platform-independent solution is recommended, such as:

- Allowing users to choose the capture interface at application startup.
- Supporting a command-line option (for example, `--interface`).
- Reading the preferred interface from a configuration file.

These approaches would improve usability across Windows, Linux, and other supported operating systems without introducing operating system–specific code into the project.

---

# 12. Sprint 4 Testing Summary

The following verification activities were completed during Sprint 4.

| Test | Status |
|------|--------|
| Project Build (`cargo build`) | ✅ Passed |
| Unit Tests (`cargo test`) | ✅ Passed |
| Packet Capture | ✅ Passed |
| Packet Parsing | ✅ Passed |
| Detection Engine | ✅ Passed |
| SQLite Integration | ✅ Passed |
| REST API (`/api/status`) | ✅ Passed |
| DBeaver Database Verification | ✅ Passed |
| Cross-platform Testing | ✅ Windows and Linux verified |

---

# Revision History

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.0 | July 2026 | Liezl Gonzaga Lizardo | Initial testing guide created during Sprint 2. |
| 2.0 | August 2026 | Liezl Gonzaga Lizardo | Expanded testing guide for Sprint 4 including SQLite integration, REST API testing, and integration testing. |
| 2.1 | August 2026 | Liezl Gonzaga Lizardo | Added Windows platform compatibility testing, packet capture verification, and documented temporary interface-selection workaround. |