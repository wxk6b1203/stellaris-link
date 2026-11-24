# systemd packaging

Two units are provided:

- `stellaris-agent.service` — dataplane agent. Needs `CAP_NET_ADMIN` to create
  the TUN device and install routes; `CAP_NET_RAW` for the optional probe.
- `stellaris-controller.service` — controller/Raft member. No capabilities.

## Install

```sh
sudo useradd --system --home /var/lib/stellaris --shell /usr/sbin/nologin stellaris
sudo install -d -o stellaris -g stellaris /etc/stellaris /var/lib/stellaris
sudo install -m 0755 target/release/stellaris-agent /usr/local/bin/
sudo install -m 0755 target/release/stellaris /usr/local/bin/
sudo install -m 0755 target/release/stellaris-controller /usr/local/bin/
sudo install -m 0644 packaging/stellaris-agent.service /etc/systemd/system/
sudo install -m 0644 packaging/stellaris-controller.service /etc/systemd/system/
sudo install -m 0600 examples/agent.toml /etc/stellaris/agent.toml   # then edit
sudo systemctl daemon-reload
sudo systemctl enable --now stellaris-agent.service
```

The units use `StateDirectory=stellaris` (`/var/lib/stellaris`) and expect the
config to keep `state_dir` under that path. For controllers set
`control.raft_dir` under `/var/lib/stellaris` as well; both units share the
same `ReadWritePaths`.

Mitigations included: `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, a narrow `CapabilityBoundingSet`, and
`LimitNOFILE`.
