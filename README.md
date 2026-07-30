# Stomper

Stomper is a network intrusion detection system written in Rust. The project goal is to capture live traffic, detect suspicious network
behavior, send alerts, and present information to the user on a local dashboard.

## Current status

The `main` branch runs the whole pipeline: it captures Ethernet traffic through
the Rust `pcap` crate, parses selected Ethernet/IPv4/IPv6/TCP/UDP/ICMP headers,
detects port scans and SYN floods, prints and stores alerts in SQLite, and serves
a local dashboard. Configuration is still compile-time: the interface is chosen
automatically, and thresholds, bind address, and database path are constants.

See the architecture document for the implementation state and target system
boundary.

## Running

```bash
cargo run
```

Capture needs elevated privileges. On Linux, either run with `sudo` or grant the
binary the capability once:

```bash
sudo setcap cap_net_raw+ep target/debug/stomper
```

The dashboard is served on <http://127.0.0.1:8080> and alerts are written to
`stomper.db` in the working directory. Press Ctrl-C to stop; queued packets and
alerts are drained before exit.

## Documentation

- [Architecture](docs/development/architecture.md) - current and target system
  architecture, component maturity, constraints, and evolution plan
- [Database](docs/development/database.md) - alert schema, access rules, and
  operational notes
- [Testing guide](docs/testing.md) - build, run, and test procedures
- [Team project plan](docs/plans/project-plan_Team05.pdf) - requirements,
  milestones, responsibilities, and original target architecture

"This quote was taken out of context." --Randall Munroe
