# IKEv2 VPN Control Panel

A dependency-aware web control panel for an existing
[hwdsl2/setup-ipsec-vpn](https://github.com/hwdsl2/setup-ipsec-vpn) IKEv2 host.

The panel does **not** install or replace Libreswan, the CA/NSS database,
certificates, client profiles, or the upstream `ikev2.sh` helper. It fails closed
unless the upstream VPN installation is already healthy.

## Requirements

- Ubuntu 24.04
- root access
- a DNS name pointing to the host
- hwdsl2/setup-ipsec-vpn installed with IKEv2 enabled

Install the upstream VPN first:

```bash
curl -fsSL https://get.vpnsetup.net -o vpn.sh
sudo VPN_DNS_NAME='vpn.example.com' sh vpn.sh
```

## Configure the panel

```bash
cp config/panel.env.example config/panel.env.local
```

Edit `config/panel.env.local` and set at least:

- `VPN_APP_NAME`
- `VPN_BRAND_NAME`
- `VPN_PUBLIC_DOMAIN`
- `VPN_SERVICE_PREFIX`
- `VPN_DEFAULT_ACCESS_GROUP`

`VPN_CHANNEL_CAPACITY_MBIT` is optional. Leave it empty until you know the real
usable uplink capacity. The panel does not invent or auto-detect this value.

Do not commit the local environment file.

## Install

```bash
sudo ./install.sh \
  --env config/panel.env.local \
  --admin-user admin
```

When no password file is supplied, the installer asks for the administrator
password twice without echoing it and rejects a mismatch or a password shorter
than 12 characters.

Before reporting success, the installer verifies the existing IKEv2 stack,
installs panel dependencies and Caddy, creates the SQLite database and owner
account, installs systemd units, starts the panel and safe background timers,
then performs a real administrator login and opens the protected home, access,
channel and identity endpoints. It also rejects unknown service states on the
initial dashboard.

## Reset the administrator password

```bash
sudo ./install.sh reset-admin-password \
  --env config/panel.env.local \
  --admin-user admin
```

The reset command asks for the new password twice, backs up the SQLite database,
replaces the password explicitly, invalidates old sessions, checks database
integrity, restarts the panel and verifies the new login.

## Update

```bash
sudo ./scripts/deploy-source.sh --env config/panel.env.local
```

Source updates do not replace VPN keys, certificates, profiles, or the upstream
helper.

## Development

```bash
make check
```

The test suite includes a real local login against a materialized tenant panel,
a deliberately corrupted optional JSON cache, honest channel defaults, live
service-state fallback and service prefixes that themselves contain `vpn`.

## Security

Never commit databases, local environment files, certificates, exported client
profiles, SSH keys, logs, or backups. Run the panel and each tenant on a separate
VPN host.

## License

MIT. See `LICENSE`.
