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

Do not commit the local environment file.

## Install

```bash
sudo ./install.sh   --env config/panel.env.local   --admin-user admin
```

The installer verifies the existing IKEv2 stack before making changes, installs
panel dependencies and Caddy, creates a new SQLite database and owner account,
installs systemd units, starts the panel and safe background timers, and checks
`/health`.

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

## Security

Never commit databases, local environment files, certificates, exported client
profiles, SSH keys, logs, or backups. Run the panel and each tenant on a separate
VPN host.

## License

MIT. See `LICENSE`.
