<p align="right"><a href="README.md">Deutsch</a> | <b>English</b></p>

<p align="center">
  <img src="fritzhole/icon.png" alt="FritzHole" width="120">
</p>

<h1 align="center">FritzHole</h1>

<p align="center">
  <b>DNS monitoring and filter management for your FRITZ!Box – right inside Home Assistant.</b><br>
  Like Pi-hole, but without running your own DNS server.
</p>

<p align="center">
  <a href="https://github.com/Milinator/fritzhole-ha/releases"><img src="https://img.shields.io/github/v/release/Milinator/fritzhole-ha?label=version" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Milinator/fritzhole-ha?label=license" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Home%20Assistant-App-41BDF5?logo=homeassistant&logoColor=white" alt="Home Assistant App">
  <img src="https://img.shields.io/badge/arch-amd64%20%7C%20aarch64-informational" alt="Architecture: amd64, aarch64">
  <img src="https://img.shields.io/badge/status-experimental-orange" alt="Status: experimental">
</p>

<p align="center">
  <a href="https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FMilinator%2Ffritzhole-ha">
    <img src="https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg" alt="Add repository to Home Assistant">
  </a>
</p>

<p align="center"><img src="docs/images/dashboard-overview.png" alt="FritzHole dashboard" width="900"><br><sub>Domains and device names anonymized for this screenshot.</sub></p>

> [!IMPORTANT]
> **Unofficial open-source project – not made by AVM.** FritzHole is a private hobby project and is not affiliated
> with AVM GmbH / FRITZ! GmbH. Please **do not contact AVM support** about FritzHole – use the
> [issues](https://github.com/Milinator/fritzhole-ha/issues) of this repository instead.

> [!NOTE]
> The user interface of FritzHole is currently **German only**. The configuration options in Home Assistant are
> available in German and English.

---

## What is FritzHole?

Recent FRITZ!OS versions come with a **built-in DNS filter**: the FRITZ!Box itself blocks ad and tracking domains,
for example using blocklists such as HaGeZi. However, the FRITZ!Box shows very little of what is actually happening.

**FritzHole makes it visible and easy to manage.** The app runs in Home Assistant, watches the DNS queries in your
home network in real time and shows in a dashboard which devices query which domains and what gets blocked.
Exceptions, filter lists and the filter itself can be managed right there.

### Why not Pi-hole or AdGuard Home?

With Pi-hole or AdGuard Home you run an **additional DNS server** and have to point all devices (or the FRITZ!Box
DHCP server) to it. If that server goes down, name resolution stops working for your entire network.

FritzHole takes a different approach:

- **The FRITZ!Box stays your DNS server.** Nothing is redirected, no device needs to be reconfigured.
- **Filtering is still done by the FRITZ!Box itself.** FritzHole only observes and manages.
- **If FritzHole is not running, your network won't notice.** Filtering keeps working independently.

## Features

**Monitoring**

- **Live DNS log** – every DNS query in your home network in real time, with device, domain, type, answer and latency
- **Blocked query detection** – the FRITZ!Box answers blocked domains with `0.0.0.0` or `::`;
  NXDOMAIN, errors and unanswered queries are distinguished as well
- **Statistics and history** – queries, block rate and errors, timeline chart, time ranges from 1 hour to 30 days
- **Insights** – top queried and top blocked domains, most active devices with their block rate,
  filters for time range, status, device and search term
- **Device detection** – device names from the FRITZ!Box, IPv4 and IPv6 addresses of one device grouped together
  (via the MAC address), custom names and manual merging

**Managing the FRITZ!Box DNS filter**

- **Allowlist and blocklist** – create, edit and delete exceptions; straight from the live log via context menu
  ("allow" / "block"), including an indicator whether a domain is already listed
- **Turn the filter on and off** – permanently or **pause it temporarily** (5, 15, 30, 60 minutes or a custom
  duration); automatic re-activation also works after the app restarts
- **Manage filter lists** – add, edit, enable/disable and delete lists, with entry count and error display per list
- **Update filter lists** – manually with progress display, or automatically using the FRITZ!Box schedule options
  (every 8 hours, daily, weekly, monthly, never)
- **FRITZ!Box statistics** – the query and block counters of the box itself

**Home Assistant**

- Dedicated dashboard in the **sidebar** (Ingress) – no open port, no extra login, visible to administrators only
  by default
- Settings via the app configuration in Home Assistant (German/English)
- All data stays local on your Home Assistant system

> [!NOTE]
> FritzHole currently provides **no Home Assistant entities** (sensors, switches). It is used through the dashboard
> in the sidebar.

## Compatibility and requirements

| FRITZ!Box | FRITZ!OS | Live log & statistics | DNS filter management | Status |
|---|---|:---:|:---:|---|
| 7530 AX | 8.40-136793 BETA (lab version) | ✅ | ✅ | **confirmed** |
| other models | 8.50 or newer | ❔ | ❔ | untested |
| any | without built-in DNS filter (before 8.50) | ❔ | ❌ | untested, DNS filter management not possible |

**Why so cautious?** FritzHole relies on FRITZ!OS interfaces that are **not officially documented**: the packet
capture of the FRITZ!Box web interface and a **beta API** for the DNS filter. AVM may change either of them with any
update, so support for every firmware version cannot be guaranteed.

> [!TIP]
> **Help us fill in this table!** Have you tried FritzHole with another model or FRITZ!OS version – successfully or
> not? Please report it via a
> [compatibility issue](https://github.com/Milinator/fritzhole-ha/issues/new?template=compatibility.md).

**Requirements**

- Home Assistant OS or Supervised (amd64 or aarch64)
- A FRITZ!Box user with the **"FRITZ!Box settings"** permission (required for packet capture and the DNS filter API)
- For DNS filter management: a FRITZ!OS version with the built-in DNS filter – introduced with FRITZ!OS 8.50 and its
  lab versions. Without it, the live log and statistics still work; the "DNS-Filter" tab then shows an error message.
- Optional, for device names: enable "Allow access for applications" (TR-064) in the FRITZ!Box

## Installation

### One click

[![Add repository to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FMilinator%2Ffritzhole-ha)

The button opens your Home Assistant and adds the repository. [My Home Assistant](https://my.home-assistant.io/)
needs to know the address of your instance – you will be asked for it on your first click.

### Manually

1. In Home Assistant, open **Settings → Apps → App store**.
2. Choose **⋮ → Repositories** in the top right corner.
3. Enter `https://github.com/Milinator/fritzhole-ha` and click **Add**.

### Next steps

1. Select **FritzHole** in the app store and click **Install**. The app is built locally on your system; the first
   build takes a few minutes.
2. On the **Configuration** tab, enter the FRITZ!Box address, user name and password, then save.
3. Click **Start** and enable **"Show in sidebar"** (enabling "Start on boot" is recommended as well).

> In older Home Assistant versions these menu items are still called "Add-ons" and "Add-on store".

## Getting started

1. **Create a FRITZ!Box user:** preferably a dedicated one, e.g. `fritzhole` (System → FRITZ!Box Users), with the
   "FRITZ!Box settings" permission.
2. **Enable the DNS filter in the FRITZ!Box** and set up at least one filter list – otherwise nothing gets blocked
   that FritzHole could show.
3. **Open FritzHole from the sidebar.** "Mitschnitt aktiv" (capture active) appears at the top once connected.
4. **"Live-Protokoll" tab (live log):** use **⋯** (or right-click) on a row to allow or block a domain.
5. **"DNS-Filter" tab:** allowlist/blocklist, pause, filter lists and automatic updates.

All options and a troubleshooting table can be found in the [app documentation](fritzhole/DOCS.md) (German).

## Known limitations

- **Undocumented interfaces:** packet capture and the DNS filter API may change with FRITZ!OS updates.
- **Home network only (LAN/Wi-Fi):** devices in the guest network and devices using **DNS over HTTPS/TLS**
  (e.g. browsers with "secure DNS") don't show up, or only partially.
- **One capture at a time:** a parallel packet capture in the FRITZ!Box web interface can interfere with FritzHole
  and vice versa.
- **DNS over TCP** is only evaluated experimentally.
- **Storage:** every DNS query is stored individually (measured at around 340 bytes each, including indexes). In networks with a lot of queries
  the database grows quickly – adjust `retention_days` and `max_events` accordingly
  (see [DOCS.md](fritzhole/DOCS.md#speicherbedarf)).
- **Subdomains:** whether an entry for `example.com` also covers `sub.example.com` is up to the FRITZ!Box.
  FritzHole marks such cases with "≈"; this behaviour has not been verified.
- So far tested with one model and one lab version only (see above).

**Ideas – not implemented yet:** excluding devices or domains from logging; more compact storage using hourly
summaries.

## Privacy and security

**What FritzHole reads**

- Via the FRITZ!Box packet capture, **DNS traffic only** (UDP/TCP port 53) of the selected interface: timestamp,
  IP and MAC address of the device, queried domain, type and answer. The FRITZ!Box does not capture any other traffic.
- Optionally the FRITZ!Box device list (IP, MAC, device name) via TR-064, every 10 minutes.
- The DNS filter configuration: exceptions, filter lists, settings and counters.

**What is stored locally**

- In an SQLite database in the app's `/data` folder: DNS events, devices (MAC, names, IP addresses) and the state of
  an active pause.
- Events are deleted automatically after `retention_days` (default 14 days) or when `max_events` is reached.
- The FRITZ!Box password is kept by Home Assistant in the app configuration; FritzHole does not write it anywhere.
  Neither the password nor session IDs appear in logs or in responses of the app.
- `/data` is included in Home Assistant backups – so your DNS log is part of your backups, too.

**What FritzHole can change on the FRITZ!Box**

FritzHole is **not a read-only tool**. The dashboard can change:

- exceptions (allowlist/blocklist): create, edit and delete
- the DNS filter: turn on, turn off or pause
- filter lists: create, edit, enable/disable, delete and update
- the interval of automatic filter list updates

Every change has to be confirmed in the dashboard and is verified afterwards by reading the configuration again.
If you only want to observe, set the option **`dnsfilter_management: false`** – the DNS filter section is then
read-only. In addition, FritzHole starts and stops the **packet capture** of the FRITZ!Box. It does not change any
other settings of the box.

**What turning off the DNS filter means**

The DNS filter applies to **all devices** that use the FRITZ!Box as their DNS server. Turning it off or pausing it
therefore disables filtering for your **entire network**. A pause turns the filter back on automatically at the
chosen time, "turn off permanently" does not.

**Access and network**

- The dashboard is only reachable through Home Assistant (Ingress) and visible to administrators only by default.
- FritzHole sends **no data to external services**.
- The connection to the FRITZ!Box uses HTTP inside your home network. The password is not transmitted in plain text
  (challenge-response or HTTP digest), the session ID is.

**Personal data:** DNS logs show which services a device uses. As soon as a device can be linked to a person, this is
personal data. Let the other people in your household know, keep the retention period short and don't log devices
whose data you are not entitled to (e.g. work computers). This is not legal advice.

## Feedback and contributing

- **Found a bug?** → [Report a bug](https://github.com/Milinator/fritzhole-ha/issues/new?template=bug_report.md)
- **Tested another FRITZ!Box model?** →
  [Report compatibility](https://github.com/Milinator/fritzhole-ha/issues/new?template=compatibility.md)
- **Ideas or questions?** → [Issues](https://github.com/Milinator/fritzhole-ha/issues) (English or German)
- **Want to contribute code?** → structure, tests and local setup are described in
  [docs/development.md](docs/development.md).

Please **do not post passwords, session IDs or complete DNS logs** in issues.

## Further documentation

| Document | Contents |
|---|---|
| [fritzhole/DOCS.md](fritzhole/DOCS.md) | App documentation: options, how it works, troubleshooting (also shown in Home Assistant) |
| [fritzhole/CHANGELOG.md](fritzhole/CHANGELOG.md) | Changes per version |
| [docs/architecture.md](docs/architecture.md) | App structure and data flow |
| [docs/fritzbox-interfaces.md](docs/fritzbox-interfaces.md) | Technical details of the FRITZ!Box communication |
| [docs/api.md](docs/api.md) | HTTP API of the dashboard |
| [docs/development.md](docs/development.md) | Development, tests, local setup, releases |

The technical documents in `docs/` as well as DOCS.md and the changelog are currently available in German only.

## License and disclaimer

FritzHole is licensed under the [MIT License](LICENSE) and provided **without any warranty**. Use it – especially for
changing FRITZ!Box settings – at your own risk.

FritzHole is an independent open-source project. It is not affiliated with AVM GmbH / FRITZ! GmbH and is not
supported, reviewed or approved by them. FRITZ!, FRITZ!Box and FRITZ!OS are trademarks of AVM GmbH / FRITZ! GmbH.
They are mentioned here solely to describe which devices FritzHole works with. This does not grant any permission
to use these trademarks or logos.
