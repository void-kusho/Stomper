# Stomper

Stomper is a network intrusion detection system written in Rust. The project goal is to capture live traffic, detect suspicious network
behavior, send alerts, and present information to the user on a local dashboard.

## Current status

The `main` branch is a packet-capture prototype. It
currently captures Ethernet traffic through the Rust `pcap` crate, parses
selected Ethernet/IPv4/IPv6/TCP/UDP/ICMP headers, and prints packet summaries
for 30 seconds. Detection, alert storage, configuration, the API, and the
dashboard are planned but not implemented.

See the architecture document for the implementation state and target system
boundary.

## Documentation

- [Architecture](docs/development/architecture.md) - current and target system
  architecture, component maturity, constraints, and evolution plan
- [Technical design](docs/development/design.md) - proposed component contracts,
  runtime behavior, data model, security, testing, and implementation gates
- [Team project plan](docs/plans/project-plan_Team05.pdf) - requirements,
  milestones, responsibilities, and original target architecture

"This quote was taken out of context." --Randall Munroe
