# AD April '26 Check0r 🛡️  
**Kerberos RC4/AES Readiness Checks for the April 2026 changes (CVE-2026-20833)**

**Created by:** Benjamin Iheukumere | SafeLink IT

---

## What is this?

Microsoft is changing how Domain Controllers (KDC) issue Kerberos service tickets. In **April 2026**, the default behavior shifts toward **AES-only** unless **RC4 is explicitly allowed** on the target account via `msDS-SupportedEncryptionTypes`.

This script helps you answer two questions:

1) **Will anything break in my AD when enforcement kicks in?**  
2) **Which devices / accounts / services are the likely culprits?**

It is designed to be **transferable** and **read-only**: it queries AD + DC event logs + (optionally) KDC registry overrides and produces a folder full of exports you can hand to ops teams.

---

## Why you should care (practical version)

RC4 is weak and heavily abused (Kerberoasting loves it).  
But legacy devices, old keytabs, and ancient service accounts can still depend on RC4 in weird ways.

The January 2026 updates introduced **new KDC “readiness” events (IDs 201–209)** in the **Domain Controller System log** to help you identify what will break *before* the April 2026 phase change.

This script collects those events and adds additional AD-side triage (SPNs, encryption flags, old passwords, etc.).

---

## What it checks

### 1) Domain Controller inventory
- Discovers DCs automatically (or uses provided `-TargetDCs`)
- Collects basic metadata (name, OS, site, IPv4, etc.)

### 2) KDC registry overrides (visibility / compatibility crutches)
Reads, per DC:
- `HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\Parameters\DefaultDomainSupportedEncTypes`
- `HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\Parameters\SupportedEncryptionTypes`

Why: If you forced DDSET to allow RC4 broadly, you can hide readiness problems until enforcement day.

### 3) KDC readiness events (System log: 201–209)
Pulls events from each DC for the last `-DaysBack` days, exports CSV + summary.

Focus events:
- **201/206**: clients/devices that don’t advertise/support AES properly (legacy clients, appliances, AES-less keytabs)
- **202/207**: accounts that need a password reset because AES keys are missing (very old passwords or hash-only migrations)

### 4) SPN-enabled accounts inventory
Finds accounts with SPNs and classifies them by:
- `msDS-SupportedEncryptionTypes` (RC4 allowed? AES only? default/unset?)
- password age heuristics (incl. “pre-2008”-style risk bucket)
- object type and key attributes

Outputs:
- Full SPN inventory CSV
- A “REVIEW” subset CSV (the stuff you’ll likely care about)

### 5) Legacy / at-risk endpoint triage (AD attribute scan)
Uses AD `OperatingSystem` strings as a quick prioritization list (not proof).
You should correlate this with the DC readiness events for evidence.

---

## Requirements

- Windows PowerShell 5.1 **or** PowerShell 7+ (Windows)
- RSAT / ActiveDirectory module available (`Get-ADDomain`, `Get-ADUser`, …)
- Network access to DCs
- Permissions:
  - **Read** access to AD objects (typical domain user is usually enough for inventory)
  - **Read** access to DC **System** event log (often “Event Log Readers” or admin-equivalent)
  - For registry checks: WinRM / remote access rights to query registry on DCs

---

## Install / Run

Clone the repo and run the script from a management host (or a DC in a lab).

Example:
```powershell
# optional: allow script execution for current session only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# run with defaults
.\ad0426_check0r.ps1
````

Recommended:

```powershell
.\ad0426_check0r.ps1 -DaysBack 14 -OutRoot "C:\Temp"
```

Target specific DCs:

```powershell
.\ad0426_check0r.ps1 -TargetDCs @("dc01.contoso.local","dc02.contoso.local") -DaysBack 30
```

---

## Output (what you get)

The script creates an output folder like:

`AD-April26-Check0r_<domain>_<yyyyMMdd-HHmmss>\`

Structure:

* `csv\`

  * `DC-Inventory.csv`
  * `DC-KdcRegistryConfig.csv`
  * `KDC-ReadinessEvents.csv`
  * `KDC-ReadinessEvents-Summary.csv`
  * `SPN-Inventory.csv`
  * `SPN-Inventory-REVIEW.csv`
  * `LegacyOS-Triage.csv` (if available)
* `report\`

  * `FindingsSummary.txt`
  * `Report.md`
* `logs\`

  * `Transcript.txt` (if Start-Transcript works in your host context)

Everything is also printed to stdout while running.

---

## How to interpret results (quick playbook)

### If you see Event 201 / 206

This is usually a **client/device** problem:

* old OS
* appliance with embedded Kerberos stack
* keytab generated without AES keys
* AES disabled / not advertised

Action:

* update/patch/replace the device
* regenerate keytabs with AES enabled
* validate by re-testing and watching the events stop

### If you see Event 202 / 207

This is usually a **service account** problem:

* password is ancient (or never rotated since “the old days”)
* migrated using tools that only migrated NTLM hashes (no AES keys derived)

Action:

* rotate password
* prefer gMSA where possible
* validate service compatibility (especially non-Windows services)

### If SPN inventory shows RC4-only or “RC4 allowed”

Treat it as:

* compatibility exception (sometimes needed), but also
* a Kerberoasting-friendly configuration

Action:

* move services to AES
* use `msDS-SupportedEncryptionTypes` as a scalpel: only allow RC4 where you truly must

---

## Notes / Gotchas

* “No events found” does **not** automatically mean “you are safe”.

  * It can also mean: not patched, logging suppressed, no relevant traffic in the window, or remote event log read failed.
* AD `OperatingSystem` strings are triage, not evidence.
* Some environments explicitly configure `DefaultDomainSupportedEncTypes`. That can mask issues until enforcement.

---

## Safety

This script is **read-only**:

* No accounts are modified
* No registry values are changed
* No services are restarted

It only queries and exports information.

---

## References (recommended reading)

* Microsoft Support: Kerberos KDC RC4 changes (CVE-2026-20833)
  [https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

* Microsoft Learn: Detect and remediate RC4 usage in Kerberos
  [https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

* Microsoft TechCommunity (AskDS): RC4 in Kerberos deep dive
  [https://techcommunity.microsoft.com/blog/askds/what-is-going-on-with-rc4-in-kerberos/4489365](https://techcommunity.microsoft.com/blog/askds/what-is-going-on-with-rc4-in-kerberos/4489365)

---

## Contributing

PRs and issues are welcome.

If you open an issue, please include:

* the script version / commit hash
* PowerShell version (`$PSVersionTable`)
* whether you ran from a DC or management host
* sanitized snippets of the failing section and error message
* whether WinRM / remote event log access is available in your environment

---

## License

Pick whatever fits your repo strategy (MIT is common for tooling like this).
Once you decide, drop the license text into `LICENSE` and keep it consistent across your repos.

---

## Disclaimer

This tool is provided “as-is”, without warranty.
Always validate changes in a lab and follow your organization’s change management process.

```

The README references Microsoft’s official guidance for the April 2026 phase change and the KDC readiness events. :contentReference[oaicite:0]{index=0}
::contentReference[oaicite:1]{index=1}
```
