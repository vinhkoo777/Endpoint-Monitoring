# Use Case - Discovery (T1033)
## MITRE ATT&CK: System Owner/User Discovery

## Phase 1: Chuẩn Bị Rule

### 1.1 Truy cập Rule Management

Đầu tiên bấm vào dấu **3 gạch** trên giao diện Wazuh Dashboard. Tiếp đó nhấn vào **Server Management** -> **Rules**.

Nhấn **Custom Rules** -> **Add new rules file**. Nhập nội dung rule bên dưới vào file, sau đó nhấn **Save** để lưu lại.

### 1.2 Nội Dung Custom Rule

```xml
<group name="windows,sysmon,user_discovery,">

    <rule id="101001" level="6">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\whoami\.exe$</field>
        <description>T1033 - System Owner/User Discovery using whoami.exe</description>
        <mitre><id>T1033</id></mitre>
    </rule>

    <rule id="101002" level="8">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\whoami\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)\s/(all|priv|groups|user|logonid|fqdn|upn)\b</field>
        <description>T1033 - Extended current user information discovery using whoami</description>
        <mitre><id>T1033</id></mitre>
    </rule>

    <rule id="101003" level="7">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\(quser|qwinsta)\.exe$</field>
        <description>T1033 - Logged-on user or session discovery detected</description>
        <mitre><id>T1033</id></mitre>
    </rule>

    <rule id="101004" level="7">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\query\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)\buser\b</field>
        <description>T1033 - Logged-on user discovery using query user</description>
        <mitre><id>T1033</id></mitre>
    </rule>

    <rule id="101005" level="8">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(WindowsIdentity\]::GetCurrent|WindowsIdentity.*GetCurrent|\$env:USERNAME)</field>
        <description>T1033 - Current user discovery using PowerShell</description>
        <mitre><id>T1033</id></mitre>
    </rule>

    <rule id="101006" level="9">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\cmd\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(whoami.*(quser|qwinsta)|quser.*qwinsta|whoami.*query\s+user)</field>
        <description>T1033 - Multiple user and session discovery commands executed through CMD</description>
        <mitre><id>T1033</id></mitre>
    </rule>

</group>
```

### 1.3 Mô Tả Rule

Toàn bộ rule tập trung vào **Sysmon Event ID 1 (Process Creation)** để phát hiện các lệnh truy vấn danh tính người dùng và session đang đăng nhập. Rule được tăng level khi command thu thập nhiều thông tin hơn hoặc kết hợp nhiều lệnh discovery.

| Rule ID | Level | Kỹ thuật phát hiện |
|---------|-------|--------------------|
| 101001 | 6 | Phát hiện thực thi `whoami.exe` |
| 101002 | 8 | `whoami` kèm `/all`, `/priv`, `/groups`, `/user`, `/logonid`, `/fqdn`, `/upn` |
| 101003 | 7 | Phát hiện `quser.exe` hoặc `qwinsta.exe` để liệt kê session |
| 101004 | 7 | Phát hiện `query.exe user` |
| 101005 | 8 | PowerShell truy vấn user qua `WindowsIdentity::GetCurrent` hoặc `$env:USERNAME` |
| 101006 | 9 | CMD thực thi nhiều lệnh user/session discovery liên tiếp |

### 1.4 Reload và Restart Service

Sau khi lưu rule, nhấn **Reload** trên giao diện Wazuh Dashboard.

Trên máy **Ubuntu Server**, restart Wazuh Manager để áp dụng rule:

```bash
sudo systemctl restart wazuh-manager
```

## Phase 2: Thực Hiện Test (Atomic Red Team)

Trên máy **Windows**, mở **PowerShell** với quyền **Administrator** và chạy:

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Invoke-AtomicTest T1033 -GetPrereqs
Invoke-AtomicTest T1033
```

## Phase 3: Alert Analysis

### 3.1 Kiểm Tra Alert Trên Wazuh Dashboard

Vào **Threat Hunting** -> tab **Events**, nhập DQL query sau vào thanh tìm kiếm:

```
rule.mitre.id:T1033
```

<img width="1912" height="392" alt="image" src="https://github.com/user-attachments/assets/5127cc64-ebd2-4590-b33c-8d8a9394672c" />

Danh sách alert sẽ hiển thị các rule được kích hoạt trong quá trình chạy Atomic Red Team. Kiểm tra `rule.id`, `rule.level`, `agent.name` và thời gian phát sinh để xác nhận alert đến đúng endpoint thực hiện test.

<img width="1907" height="921" alt="image" src="https://github.com/user-attachments/assets/855bdf64-56ef-41ea-90d1-685a1ae0d5dd" />

### 3.2 Phân Tích Chi Tiết Alert: Case Study: Extended User Discovery bằng whoami (Rule 101002)

Nhấn vào alert **Rule 101002** để kiểm tra hành vi `whoami` thu thập thông tin mở rộng về tài khoản hiện tại. Đây là hành vi discovery thường xuất hiện sau khi attacker có được quyền thực thi lệnh trên endpoint.

**Các field cần tập trung khi mở Document Details:**

- `data.win.eventdata.image` đường dẫn tới `whoami.exe`
- `data.win.eventdata.commandLine` tham số như `/all`, `/priv`, `/groups`
- `data.win.eventdata.parentImage` tiến trình đã gọi `whoami.exe`
- `data.win.eventdata.user` tài khoản thực thi tiến trình

<img width="1297" height="955" alt="image" src="https://github.com/user-attachments/assets/56235775-12c7-4729-a230-5df6004fffd0" />

**Chuỗi hành vi có thể tái hiện:**

```
powershell.exe / cmd.exe
  └── whoami.exe /all
        └── Thu thập user, group và privilege của tài khoản hiện tại
```

Việc phát hiện `whoami /all` giúp SOC nhận biết giai đoạn **Discovery** sau initial access. Bản thân `whoami` có thể hợp lệ, vì vậy cần kết hợp parent process, command line và các alert lân cận để giảm false positive.
