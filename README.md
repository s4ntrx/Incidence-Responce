# Incident Response: Tier-1 Analyst Timeline & Triage

## 1. Methodology & Tooling
Using only standard Linux CLI tools, I parsed the provided logs using `grep`, `awk`, and `jq` to isolate anomalous activity from baseline noise. 

**Commands used:**
*   `grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr` (Identify brute force sources)
*   `grep "Accepted password" /var/log/auth.log` (Identify successful logins)
*   `jq 'select(.EventID == 1)' sysmon.json | grep "Image"` (Extract process creation events)
*   `awk '{print $1, $7, $9}' /var/log/apache2/access.log | grep -E "\.\./|union|select"` (Search for web exploitation attempts)

## 2. Chronological Timeline (UTC)

| Time (UTC) | Log Source | Event Description | Classification |
| :--- | :--- | :--- | :--- |
| 10:00:01 | `auth.log` | Multiple failed SSH logins from `192.168.1.50` for user `root` (15 attempts in 30s). | **Suspicious** (Brute Force) |
| 10:02:15 | `auth.log` | Successful SSH login for user `admin` from external IP `203.0.113.45`. | **Suspicious** (Unauthorized Access) |
| 10:03:10 | `Sysmon` (ID 1) | Process creation: `cmd.exe /c whoami` executed by user `admin`. | **Suspicious** (Discovery) |
| 10:04:22 | `web_access.log` | `GET /wp-admin/admin-ajax.php?action=...` returning HTTP 200 from `203.0.113.45`. | **Suspicious** (C2/Exploit) |
| 10:05:00 | `auth.log` | Failed login attempt for user `backup` from internal IP `10.0.0.15`. | **Benign** (Typo by admin) |
| 10:06:30 | `Sysmon` (ID 11) | File created: `C:\Windows\Temp\update.exe`. | **Suspicious** (Malware Drop) |

## 3. Anomaly Classification (Benign vs. Suspicious)

*   **SUSPICIOUS: SSH Brute Force (10:00:01)** 
    *   *Reasoning:* The high volume of rapid failed logins targeting the `root` account from a single IP is a classic credential stuffing/brute force signature, not human error.
*   **SUSPICIOUS: Successful Login from External IP (10:02:15)** 
    *   *Reasoning:* The user `admin` successfully logged in from a known malicious external IP immediately following a brute force attempt. This indicates a successful compromise.
*   **SUSPICIOUS: Process Execution & File Drop (10:03:10 & 10:06:30)** 
    *   *Reasoning:* Running `whoami` via `cmd.exe` is a common discovery tactic to establish privilege level. Dropping `update.exe` in the `Temp` directory is a highly common malware stager location.
*   **BENIGN: Failed login for `backup` (10:05:00)** 
    *   *Reasoning:* Occurred from an internal IP (`10.0.0.15`), which is typical for an internal admin mistyping a password. No subsequent anomalous activity followed from this source.

## 4. What I'd Alert On (Monitoring Recommendations)
To catch this faster next time, I would implement the following tool-agnostic alerts in a SIEM or log aggregator:

1.  **Authentication Alert:** Alert when >10 failed SSH logins occur from a single source IP within 1 minute (Detects brute force).
2.  **Impossible Travel:** Alert on a successful SSH login from an external IP if the user's baseline is internal-only (Detects unauthorized access).
3.  **Process Execution Alert:** Alert on the execution of built-in discovery commands (`whoami`, `net user`, `ipconfig`) when spawned by a web server process or immediately following a remote login.
4.  **File Integrity Monitoring (FIM):** Alert on the creation of `.exe` files inside `C:\Windows\Temp\` or `/tmp/` (Detects malware staging).
