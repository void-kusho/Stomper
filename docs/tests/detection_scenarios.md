# Detection Scenarios Test Plan

**Project:** Stomper – Rust Network Intrusion Detection System (IDS)  
**Course:** CSE 499 – Senior Software Engineering Project  
**Team:** Team 05  
**Sprint:** Sprint 2  
**Version:** 1.0

---

# 1. Purpose

This document defines the attack scenarios used to validate the Detection Engine of the Stomper Network Intrusion Detection System (IDS).

The Detection Engine analyzes parsed network packets and identifies suspicious behavior such as port scanning and SYN flood attacks. These scenarios ensure the detection logic correctly identifies malicious activity while minimizing false positives.

---

# 2. Objectives

The objectives of detection testing are to:

- Verify detection of common network attacks.
- Ensure legitimate network traffic does not trigger false alarms.
- Validate alert generation for detected attacks.
- Confirm detection thresholds operate as expected.
- Support regression testing during future development.

---

# 3. Test Environment

| Item | Value |
|------|-------|
| Operating System | Windows 11 / macOS / Linux |
| Rust | 1.97.0 or later |
| Packet Source | Live Traffic / Test Traffic |
| Detection Module | `src/detection/` |
| Alert Module | `src/alert/` |

---

# 4. Detection Scenarios

## DET-001 – Normal Web Browsing

### Objective

Verify that normal web browsing traffic is not detected as malicious.

### Test Steps

1. Start packet capture.
2. Browse several websites.
3. Observe the detection engine.

### Expected Result

- No alerts generated.
- Packets processed normally.
- Application remains stable.

---

## DET-002 – SSH Connection

### Objective

Verify that normal SSH traffic does not trigger an alert.

### Test Steps

1. Establish an SSH connection.
2. Exchange normal traffic.

### Expected Result

- No attack detected.
- Connection processed successfully.

---

## DET-003 – Port Scan Detection

### Objective

Verify that repeated connection attempts to multiple ports are identified as a port scan.

### Test Steps

1. Generate a port scan using a testing tool or simulation.
2. Observe detection output.

### Expected Result

- Port Scan alert generated.
- Source IP recorded.
- Timestamp included.
- Alert severity displayed.

---

## DET-004 – SYN Flood Detection

### Objective

Verify excessive TCP SYN packets are detected.

### Test Steps

1. Generate repeated TCP SYN packets.
2. Observe detection engine.

### Expected Result

- SYN Flood alert generated.
- Source IP identified.
- Alert severity displayed.
- Packet count recorded (if implemented).

---

## DET-005 – DNS Traffic

### Objective

Verify normal DNS queries do not trigger alerts.

### Test Steps

1. Perform several DNS lookups.
2. Observe detection results.

### Expected Result

- No alerts generated.
- DNS packets processed successfully.

---

## DET-006 – Mixed Network Traffic

### Objective

Verify detection accuracy during normal mixed network activity.

### Test Steps

1. Browse websites.
2. Stream media.
3. Download a file.
4. Perform DNS lookups.

### Expected Result

- No false positives.
- Stable application performance.

---

## DET-007 – Repeated Connection Attempts Below Threshold

### Objective

Verify that traffic below the detection threshold does not generate alerts.

### Test Steps

1. Generate several connection attempts below the configured threshold.
2. Observe detection output.

### Expected Result

- No alert generated.
- Activity logged normally.

---

## DET-008 – Multiple Simultaneous Events

### Objective

Verify the Detection Engine handles multiple events correctly.

### Test Steps

1. Generate normal traffic.
2. Generate a port scan.
3. Generate a SYN flood.

### Expected Result

- Each attack detected independently.
- Alerts displayed correctly.
- Application remains responsive.

---

# 5. Alert Verification Checklist

When an attack is detected, verify the alert includes:

- Timestamp
- Attack Type
- Source IP Address
- Destination IP Address (if available)
- Severity Level
- Additional details (ports, packet count, etc.)

Example:

```text
[2026-07-23 10:30:15]

ALERT: Port Scan Detected

Source IP:
192.168.1.25

Target:
192.168.1.100

Ports:
22, 80, 443

Severity:
Medium
```

---

# 6. Acceptance Criteria

The Detection Engine passes testing when:

- Port scans are detected correctly.
- SYN flood attacks are detected correctly.
- Legitimate traffic does not trigger alerts.
- Alerts contain complete information.
- No application crashes occur during testing.

---

# 7. Test Execution Log

| Test ID | Tester | Date | Result | Notes |
|----------|--------|------|--------|-------|
| DET-001 | | | Pass / Fail | |
| DET-002 | | | Pass / Fail | |
| DET-003 | | | Pass / Fail | |
| DET-004 | | | Pass / Fail | |
| DET-005 | | | Pass / Fail | |
| DET-006 | | | Pass / Fail | |
| DET-007 | | | Pass / Fail | |
| DET-008 | | | Pass / Fail | |

---

# 8. Risks

Potential risks during testing include:

- Platform-specific differences in packet capture.
- Incomplete or malformed packet data.
- Incorrect detection thresholds.
- High network traffic affecting test results.
- Detection logic still under development.

---

# 9. Future Enhancements

Future testing may include:

- ICMP Flood Detection
- UDP Flood Detection
- ARP Spoofing Detection
- Brute Force Login Detection
- DDoS Detection
- Signature-based Attack Detection
- Anomaly-based Detection
- Automated integration tests

---

# Revision History

| Version | Date | Author | Description |
|----------|------|--------|-------------|
| 1.0 | July 2026 | Liezl Gonzaga Lizardo | Initial Detection Scenarios Test Plan created for Sprint 2. |