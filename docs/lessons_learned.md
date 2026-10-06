# 📚 Lessons Learned

## 🗂️ Data source

**Relay servers corrupt 4624-based mappings.**
SCCM management points and Windows Event Collectors appeared with workstation IPs, because they
handle traffic on behalf of other hosts. `Workstation_Name` + `Network Address` is unreliable near them.

**Machine accounts identify the host itself.**
An account ending in `$` is the computer authenticating as itself, which ties the IP to the real host
rather than to an intermediary.

**Domain controllers authenticate to themselves over loopback (`::1`).**
That address is filtered out, so DCs are added to the lookup manually.

## ⚡ Performance

**`tstats` is only fast inside the acceleration summary range.**
With a 1-day range, longer searches silently fell back to raw events: fast at first, then crawling.
Size the summary range to the longest search that depends on it.

**`append [inputlookup]` + `dedup` scales with the lookup.**
Each run reads the full table. If it becomes slow, write with `outputlookup append=true` and dedup in a
separate daily search.

## 🧭 Field normalization

**A field's value type isn't guaranteed.**
`src` holds an IP in some notables and a hostname in others, so the macro resolves in both directions
rather than assuming IP input.

**Endpoint fields are relative to the endpoint, not the connection.**
Trellix `LocalAddress` / `RemoteAddress` map to src/dest only for outbound traffic; inbound reverses them.

**Enrich at alert time, not view time.**
The macro stores the resolved value when the notable is created, so it reflects the mapping at that
moment and works on `tstats` results. View-time lookups re-resolve against the current table and can
overwrite stored values.

## 🧠 Design decisions

**Authentication logs over DHCP**
- Static-IP servers never appear in DHCP logs but do authenticate to the domain.
- DC authentication logs are almost always in the SIEM already; DHCP logs often aren't.
- A machine-account logon proves the host was active from that IP, not only that a lease was issued.
- The lookup is source-agnostic: DHCP can be added as a second feed.

**Macro over ES Asset & Identity**
A&I is native and adds priority and owner context, but correlates only `src`, `dest` and `dvc`, and
adds merge searches and KV store collections to maintain. Worth revisiting if an authoritative asset
source (AD export, CMDB) becomes available.

## 🚧 Known limitations

- **No time awareness:** an IP maps to its latest host, so old notables on reused DHCP IPs may show the
  wrong hostname. Time-based lookups address this.
- **Domain-joined hosts only**, unless added manually.
- **NAT / VPN:** multiple hosts behind one IP resolve unpredictably.
- **Multivalue fields:** unmatched values in a field like `target_ips` are dropped from `dst_resolved`;
  the original field still shows them.
