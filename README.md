# Wazuh SIEM Lab - lsass Credential Access Detection (T1003.001)

**Tools:** Wazuh 4.x, Sysmon (SwiftOnSecurity config, modified), PowerShell  
**Platform:** Proxmox homelab - Ubuntu 22.04 (Wazuh manager), Windows 11 (monitored endpoint)  
**MITRE ATT&CK:** T1003.001

---

## Objective

Detect a credential access attempt targeting lsass.exe using Sysmon Event ID 10 (ProcessAccess). Document the detection gap in Wazuh's built-in ruleset, identify a false positive from a legitimate security tool, and write a custom rule that closes the gap while filtering out the noise.

---

## Environment

| VM | OS | Role | IP |
|---|---|---|---|
| wazuh-manager | Ubuntu 22.04 | Wazuh Server + Dashboard | 192.168.1.x |
| DESKTOP-72VLLG0 | Windows 11 | Monitored endpoint (Wazuh agent + Sysmon) | 192.168.1.162 |

Sysmon deployed with a modified SwiftOnSecurity config. The default config excludes `powershell.exe` from ProcessAccess logging -- that exclusion was removed to enable detection of the simulated attack. See the Environment Challenges section for context on why this matters.

---

## Background -- Why lsass

lsass.exe (Local Security Authority Subsystem Service) handles Windows authentication and stores credential material in memory. Tools like Mimikatz target it specifically by opening a high-privilege handle and reading process memory to extract password hashes, Kerberos tickets, and in some configurations, plaintext credentials.

The specific access mask Mimikatz requests is `0x1FFFFF` (PROCESS_ALL_ACCESS). This value is the primary detection signal -- it's far more permissive than what legitimate system processes need when interacting with lsass. Sysmon logs both the source process and the access mask on every lsass handle request, which makes it possible to distinguish attacker behavior from normal system activity.

---

## Environment Challenges

This lab ran into two Windows 11 security controls worth documenting because they're relevant in real environments:

**LSA Protection (RunAsPPL)**

Windows 11 enables LSA Protection by default, which marks lsass as a Protected Process Light (PPL). This blocks even administrator-level processes from opening high-privilege handles to lsass. ProcDump, comsvcs.dll MiniDump, and similar tools all fail against a PPL-protected lsass without a kernel-level driver.

Disabled via registry for this lab:
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 0
```
Requires a reboot to take effect. In a real environment, LSA Protection being enabled is a meaningful defensive control -- its absence on a host is worth flagging as a configuration finding.

**SwiftOnSecurity Sysmon Config Filtering**

The SwiftOnSecurity config ships with powershell.exe excluded from ProcessAccess logging by design. This is a deliberate noise reduction decision -- PowerShell legitimately accesses many processes during normal operation and logging all of it generates significant volume.

The relevant exclusion at line 304:
```xml
<Image condition="image">powershell.exe</Image>
```

Removing this line from the ProcessAccess exclude block allows Sysmon to log the attack simulation. In production, the tradeoff between visibility and volume is a real tuning decision -- not a config error.

---

## Attack Simulation

The simulation uses a PowerShell script that calls the Windows `OpenProcess` API directly with `PROCESS_ALL_ACCESS (0x1FFFFF)`. This generates the exact same Sysmon Event ID 10 telemetry that Mimikatz produces when it stages credential access, without requiring any offensive tooling.

```powershell
$sig = @'
[DllImport("kernel32.dll")]
public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
'@
$kernel32 = Add-Type -MemberDefinition $sig -Name 'Kernel32' -Namespace 'Win32' -PassThru
$lsassId = (Get-Process lsass).Id
$handle = $kernel32::OpenProcess(0x1FFFFF, $false, $lsassId)
Write-Host "Handle opened: $handle"
```

A non-zero handle value confirms the access was granted. The `CallTrace` in the resulting Sysmon event shows `UNKNOWN` for the memory region -- this is expected when calling the API directly without an associated module on disk, and is itself a detection signal in more advanced hunting scenarios.

---

## Detection Results -- Built-in Rules

Enabling the lsass ProcessAccess rule in Sysmon immediately generated alerts, but not from the expected source:

| Rule ID | Level | Source Process | GrantedAccess | Description |
|---|---|---|---|---|
| 92900 | 12 | MsMpEng.exe (Defender) | 0x101000 | Lsass accessed with read permissions |
| 92900 | 12 | MsMpEng.exe (Defender) | 0x1010 | Lsass accessed with read permissions |

Windows Defender regularly accesses lsass memory as part of its own threat scanning -- this is normal behavior. Rule 92900 fired on Defender before the simulated attack script even ran, which means in a real environment this rule would generate continuous alerts from legitimate AV activity.

The `GrantedAccess` values tell the story:
- Defender uses `0x101000` and `0x1010` -- limited read permissions for scanning
- Mimikatz and the simulation use `0x1FFFFF` -- full process access

This distinction is what separates a false positive from a true positive.

---

## GrantedAccess Reference

| Access Mask | Name | Meaning |
|---|---|---|
| `0x1FFFFF` | PROCESS_ALL_ACCESS | Full access -- used by Mimikatz, credential dumpers |
| `0x101000` | Limited read | Common for AV scanning tools |
| `0x1010` | Query/read limited | Minimal access, typically benign |
| `0x1410` | Read + query info | Common for diagnostic tools |

---

## Custom Detection Rule

Wazuh's built-in 92900 has no mechanism to distinguish attacker access from Defender access. The custom rule below keys specifically on `0x1FFFFF` and excludes known-legitimate processes:

```xml
<!--
  Rule 100005
  Purpose: Detect PROCESS_ALL_ACCESS (0x1FFFFF) handle requests against lsass.exe.
           This access mask is used by Mimikatz and other credential dumping tools.
           Filters out known legitimate sources like Defender (MsMpEng.exe).
           Simulation performed using PowerShell OpenProcess() call.
  MITRE: T1003.001 - OS Credential Dumping: LSASS Memory
-->
<rule id="100005" level="15">
  <if_sid>61612</if_sid>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
  <field name="win.eventdata.grantedAccess">0x1FFFFF</field>
  <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)MsMpEng\.exe</field>
  <description>CRITICAL: Possible credential dump - PROCESS_ALL_ACCESS handle opened on lsass.exe by $(win.eventdata.sourceImage) [T1003.001]</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
  <group>credential_access,lsass_access,</group>
</rule>
```

**Why level 15:** This is the maximum Wazuh severity. A non-Defender process opening a full-access handle to lsass is about as unambiguous a credential access signal as exists in Windows telemetry -- there is no legitimate use case for `0x1FFFFF` on lsass outside of security tooling that would already be in an exclusion list.

**The negate filter:** The `negate="yes"` attribute inverts the match -- the rule fires on anything that is NOT MsMpEng.exe. In a production deployment this exclusion list would grow to include other known-legitimate tools (EDR agents, backup software, etc.). Starting with just Defender is appropriate for this environment.

---

## Detection Results -- Custom Rule

| Rule ID | Level | Source Process | GrantedAccess | Result |
|---|---|---|---|---|
| 92900 | 12 | MsMpEng.exe | 0x101000 | False positive -- Defender scanning |
| 100005 | 15 | powershell.exe | 0x1FFFFF | True positive -- simulated credential dump |

Both rules fire simultaneously on the same event window. The contrast in the Wazuh dashboard is the key takeaway -- 92900 fires repeatedly from a known-legitimate source while 100005 fires once from powershell.exe with a full-access mask.

---

## Lessons Learned

**The access mask is the signal, not the target process.** Every security tool fires on lsass. What differentiates attacker behavior is the permissions requested. `0x1FFFFF` on lsass from a non-EDR process is high-confidence.

**False positives require source process context.** Rule 92900 is not wrong -- Defender is accessing lsass, and in theory that could be suspicious. But without the source process in scope, the rule fires constantly on expected behavior. The custom rule adds that context and makes the detection actionable.

**Default Sysmon configs are tuned for noise reduction, not maximum visibility.** The SwiftOnSecurity config excluded powershell.exe from ProcessAccess logging for a legitimate reason. Removing that exclusion increases visibility but also increases volume. This is a real detection engineering tradeoff, not a config mistake -- and understanding it is more useful than just following a tutorial that assumes the logs are already there.

**LSA Protection is a meaningful defensive control.** The difficulty in simulating this attack on Windows 11 is the point. In a real SOC, a host without LSA Protection enabled is worth flagging -- it's a configuration gap that makes credential dumping significantly easier for an attacker.

**The `UNKNOWN` CallTrace entry is notable.** The simulation's call trace shows `UNKNOWN(00007FFB9A78DC28)` for the memory region that initiated the handle request. This happens because the API was called directly without an on-disk module backing the memory address. In threat hunting, unbacked memory regions making sensitive API calls are a higher-confidence indicator than process name alone.

---

## Repo Structure

```
wazuh-lsass-detection-lab/
├── README.md
├── rules/
│   └── local_rules.xml
├── alerts/
│   └── *.json
└── screenshots/
    └── 01-detection-results.png
```

---

## References

- [Wazuh Rules Syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK T1003.001 -- OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft -- Configuring Additional LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Windows Process Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
