# Case-04: Traffic Analysis Exercise – Kongtuke Rebuke

## 1. Executive Summary & Environment Scope
An investigation was conducted on a network packet capture (`.pcap`) following a suspected Kongtuke ClickFix compromise in an Active Directory environment. The scope of the monitored local segment included:

* **LAN Subnet Range:** `10.9.11.0/24`
* **Domain:** `overhands.org`
* **Active Directory Domain Controller:** `10.9.11.2` (`WIN-GTWXC9UYSE4`)
* **Default Gateway:** `10.9.11.1`
* **Broadcast Address:** `10.9.11.255`

---

## 2. Compromised Host Details

| Parameter | Identified Value | Investigation Protocol / Source |
| :--- | :--- | :--- |
| **Infected Host IP** | `10.9.11.135` | IPv4 Conversations analysis (high-volume outbound data flow) |
| **Infected Host MAC Address** | `08:d4:0c:7a:29:1e` | Frame Layer / Ethernet II Header (Intel OUI) |
| **Host Name** | `DESKTOP-6T17ZFM` | Kerberos `as-req` `HostAddress` attribute (`DESKTOP-6T17ZFM<20>`) |
| **User Account Name** | `gmcdowell` | Kerberos `cname-string` principal name |
| **User Full Name** | `Gabriel McDowell` | SAMR `QueryUserInfo` (Level 21) response structure |

---

## 3. Investigation Methodology & Evidence Extraction

### Step 1: Identifying Anomalous Traffic & Host IP
* **Method:** Navigated to **Statistics $\rightarrow$ Conversations** and evaluated the **IPv4** tab.
* **Finding:** While checking the `10.9.11.0/24` subnet, IP address `10.9.11.135` showed significant outbound connection activity to external public IPs (including high-throughput HTTPS streams to external Cloudflare IP blocks), singling it out as the affected host.

### Step 2: Layer 2 Hardware Identification (MAC Address)
* **Method:** Filtered for traffic initiated by `10.9.11.135` (`ip.src == 10.9.11.135`).
* **Finding:** Inspected the **Ethernet II** protocol layer in the packet details pane. The source hardware MAC address was confirmed as `08:d4:0c:7a:29:1e` (Intel vendor prefix).

### Step 3: Domain Identity & Account Extraction (Kerberos)
* **Filter:** `kerberos.CNameString`
* **Method:** Inspected Kerberos authentication tickets exchanged between client `10.9.11.135` and Domain Controller `10.9.11.2` (Port 88).
* **Finding:** 
  * Under `as-req` $\rightarrow$ `req-body` $\rightarrow$ `cname` $\rightarrow$ `cname-string`, the user account was recorded as **`gmcdowell`**.
  * Within the same request body under `addresses` $\rightarrow$ `HostAddress`, the host registered as **`DESKTOP-6T17ZFM<20>`**, establishing the Windows computer name as **`DESKTOP-6T17ZFM`**.

### Step 4: Extracting Full User Name via Cleartext SAMR Queries
* **Filter:** `samr && ip.src == 10.9.11.2` (or `samr.level == 21`)
* **Method:** Analyzed Security Account Manager Remote (SAMR) DCE/RPC traffic over the SMB named pipe `\pipe\samr`.
* **Finding:** Inspected the `QueryUserInfo` response (Level 21 - `UserAllInformation`). Because DCE/RPC payload encryption was not enforced across this administrative session, user profile attributes were transmitted in cleartext. Expanding the `UserInfo` structure directly resolved account `gmcdowell` to the full name **`Gabriel McDowell`**.

---

## 4. Key Takeaways & Security Implications
1. **Cleartext Metadata Exposure:** Administrative protocols such as unsealed SAMR/RPC over SMB expose account details and directory architecture to passive network eavesdropping.
2. **Persistence of Host Identity:** While IP allocations through DHCP are transient, extracting immutable hardware MACs and Active Directory Kerberos host tickets enables direct attribution and rapid host containment during incident response.
