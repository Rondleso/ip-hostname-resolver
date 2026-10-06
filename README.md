# 🔁 IP ⇄ Hostname Resolver for Splunk ES Notables

![Splunk](https://img.shields.io/badge/Splunk-Enterprise-000000?logo=splunk&logoColor=white)
![Enterprise Security](https://img.shields.io/badge/Splunk-Enterprise%20Security-65A637)
![SPL](https://img.shields.io/badge/language-SPL-blue)
![CIM](https://img.shields.io/badge/CIM-Authentication-orange)

> Resolve IPs to hostnames (and back) on every notable, so analysts triage without manual pivots.

## 🧩 Problem
Many notables in Splunk ES Incident Review show only a raw source or destination IP, because the
underlying events and datamodels carry no hostname. Analysts pivot manually to identify the machine
on every alert, which slows triage.

## 🎯 Goal
Show the hostname next to the IP on every notable (title, fields, Incident Review columns) without
changing any detection logic.

## 💡 Solution
- A scheduled search maintains a lookup that maps IPs to hostnames.
- A macro at the end of each correlation search resolves IPs to hostnames (and hostnames to IPs),
  falling back to the original value when there's no match.

## 🏗️ Architecture

<img width="1560" height="760" alt="ip_hostname_resolver" src="https://github.com/user-attachments/assets/9eb4fc8c-275d-4f6d-8f93-45c77d912de1" />

- **Build:** a daily report reads machine-account logons and merges them into the lookup.
- **Use:** each correlation search calls the macro, which writes `src_resolved` / `dst_resolved` into the notable.
- The two sides share only the lookup definition, so either can change independently.

## 📋 Requirements
- **Splunk Enterprise with Enterprise Security** (notables and Incident Review). The lookup and macro
  also work in plain Splunk searches.
- **CIM Authentication datamodel** populated with Windows domain authentication events in which machine
  accounts (`HOST$`) appear, e.g. via the Splunk Add-on for Microsoft Windows.
- **Datamodel acceleration** on Authentication, with a summary range of at least 2 days.
- **Permissions:** admin rights to create lookups, macros and scheduled searches; `ess_admin` to change
  Incident Review settings.
- **Optional:** the Lookup Editor app, for manual lookup entries.

## 📁 Repository layout

```
ip-hostname-resolver/
├── README.md
├── spl/
│   ├── 01_correlation_report.spl   # scheduled report
│   └── 02_macros.spl               # macro definitions, annotated
├── conf/
│   ├── transforms.conf             # lookup definition
│   └── macros.conf                 # macros for app deployment
└── docs/
    ├── lessons_learned.md          # design decisions, gotchas, limitations
    └── ip_hostname_resolver.drawio # architecture diagram source
```

Design decisions (authentication logs vs. DHCP, macro vs. ES Asset & Identity) and known limitations
are in [docs/lessons_learned.md](docs/lessons_learned.md).

## ⚙️ Implementation

### 1️⃣ Step 1: Lookup file and definition
- **File:** `ip_hostname_correlation_lookup.csv`, created with the header `IpAddress,Hostname`.
- **Definition:** `ip_hostname_correlation_lookup`, file-based, with **case-sensitive match off**
  (hostname casing varies across sources).

Only the scheduled report writes to the file; everything else reads it through the definition.

### 2️⃣ Step 2: Scheduled report
Runs daily over `-25h` (one hour of buffer for delayed runs). It takes `Authentication.src` as the
IP and `Authentication.user`, filtered to machine accounts (`HOST$`), as the hostname.

````spl
| tstats count FROM datamodel=Authentication
    WHERE NOT Authentication.src IN ("-", "unknown", "::1", "127.0.0.1")    ```drop placeholder and loopback IPs```
    BY Authentication.src, Authentication.user
| search Authentication.user="*$*"                                          ```keep machine accounts only (HOST$)```
| rename Authentication.src AS IpAddress, Authentication.user AS Hostname
| eval Hostname=replace(Hostname, "\$.*", "")                               ```strip "$" and any domain suffix```
| table IpAddress, Hostname
| dedup Hostname                                                            ```one row per host from this run```
| append [ | inputlookup ip_hostname_correlation_lookup.csv ]               ```add existing rows AFTER the new ones```
| dedup Hostname                                                            ```first row wins: new data overrides, unseen hosts are kept```
| outputlookup ip_hostname_correlation_lookup.csv
````

**Merge logic:** this run's rows precede the existing ones, and `dedup` keeps the first row per
hostname. Hosts seen again get their IP updated; hosts not seen are kept unchanged.

> [!NOTE]
> Adjust the machine-account filter (`*$*`) to your environment's account format.
> The Authentication datamodel's acceleration summary range must cover the report's time range
> (2 days for a daily run); beyond it, `tstats` falls back to raw events and slows sharply.

**Manual entries**
Since unseen rows are kept, rows added by hand (e.g. via the Lookup Editor app) persist across runs.
Use them for what authentication data can't see:
- **Domain controllers:** they authenticate to themselves as `::1`, which is filtered out.
- **Non-domain assets:** printers, network devices, appliances, non-domain Linux.
- **Shared infrastructure:** readable names for VIPs, load balancers or NAT gateways.

A manual row is replaced only if the report later sees the same hostname from another IP. Names the
report never produces (e.g. `LB-WEB-VIP`) are effectively permanent.

### 3️⃣ Step 3: Resolver macros
Two macros share one name and differ only in the first line, which selects the input fields.

**`ip_hostname_resolver`** (no arguments), for event-based alerts:

````spl
eval tmp_src=coalesce(src_ip, IpAddress, LocalAddress, src),
     tmp_dst=coalesce(dst_ip, RemoteAddress)                                         ```first IP field that exists```
| lookup ip_hostname_correlation_lookup IpAddress AS tmp_src OUTPUTNEW Hostname AS src_resolved     ```IP -> hostname```
| lookup ip_hostname_correlation_lookup Hostname AS tmp_src OUTPUTNEW IpAddress AS src_resolved     ```hostname -> IP```
| lookup ip_hostname_correlation_lookup IpAddress AS tmp_dst OUTPUTNEW Hostname AS dst_resolved
| lookup ip_hostname_correlation_lookup Hostname AS tmp_dst OUTPUTNEW IpAddress AS dst_resolved
| eval src_resolved=coalesce(src_resolved, tmp_src),
       dst_resolved=coalesce(dst_resolved, tmp_dst)                                  ```no match: keep original```
| fields - tmp_src, tmp_dst                                                          ```remove helper fields```
````

**`ip_hostname_resolver(1)`**, argument `dm` (datamodel prefix), for `tstats` alerts. First line only:

````spl
eval tmp_src=coalesce('$dm$.src', '$dm$.src_ip', src_ip, IpAddress),
     tmp_dst=coalesce('$dm$.dest', '$dm$.dest_ip', dst_ip, target_ips)
````

> [!TIP]
> The `coalesce` lists are the only part to adapt: list your environment's IP fields in order of
> preference. Fields absent from an alert are skipped.

**Settings:** start the definition with `eval`, not `| eval`. Leave "Use eval-based definition" and
validation empty. Original IP fields are never modified.

### 4️⃣ Step 4: Usage
Add the macro as the **last line** of a correlation search, after all detection logic:

```spl
| `ip_hostname_resolver`                   ``` event-based alerts ```
| `ip_hostname_resolver(Authentication)`   ``` tstats on Authentication ```
| `ip_hostname_resolver(All_Traffic)`      ``` tstats on Network_Traffic ```
```

It creates `src_resolved` and `dst_resolved`:

| Input value | In lookup | Resolved value |
|---|---|---|
| IP | yes | hostname |
| Hostname | yes | IP |
| IP or hostname | no | original value |
| field missing | — | not created |

**Display**
- **Title/description:** use tokens, e.g. `Suspicious logon from $src_resolved$`.
- **Incident Review:** add both fields under Configure → Incident Management → Incident Review
  Settings → Table Attributes and Event Attributes (applies to all users).

> [!WARNING]
> If a `| table` or `| fields` follows the macro, include both fields in it or they're dropped.

### 5️⃣ Step 5: Permissions
Every object needs its own sharing. One object left app-scoped or private breaks the chain silently,
producing empty fields with no error.

| Object | Sharing | Read | Write |
|---|---|---|---|
| Lookup file | All apps | Everyone | Admins |
| Lookup definition | All apps | Everyone | Admins |
| Macros | All apps | Everyone | Admins |
| Automatic lookups (optional) | All apps | Everyone | Admins |
| Scheduled report | Its app | Admins | Admins |

The report must run as a user who can read the Authentication datamodel and write the lookup.

## 🔌 Optional: automatic lookups
Splunk can apply the lookup to every search containing a matching field, with no change to
correlation searches. Create one entry per IP field under **Settings → Lookups → Automatic lookups**:

| Setting | Value |
|---|---|
| Lookup table | `ip_hostname_correlation_lookup` |
| Apply to | `source` = `*` (`sourcetype = *` was unreliable in testing) |
| Input fields | `IpAddress` = `src_ip` |
| Output fields | `Hostname` = `src_resolved` |
| Overwrite field values | unchecked |

**✅ Pros**
- One setup covers every alert, ad-hoc search and existing notable.
- Search-time only; removable at any time.

**⚠️ Cons**
- **No fallback:** unmatched IPs leave the field empty. Calculated fields run before lookups, so
  they can't fill the gap.
- **One entry per field**, and no handling of fields that mix IPs and hostnames.
- **No `tstats` support:** automatic lookups run on events only.
- **Overwrite conflicts:** lookups rerun when a notable is viewed; with overwrite on, a miss wipes
  the value the macro stored.

To combine with the macro, keep overwrite unchecked: macro values win, and the automatic lookup only
fills notables from alerts without the macro.
