# Use Case - Execution (T1059.003)
## MITRE ATT&CK: Command and Scripting Interpreter - Windows Command Shell

## Phase 1: Chuẩn Bị Rule

### 1.1 Truy cập Rule Management

Đầu tiên bấm vào dấu **3 gạch** trên giao diện Wazuh Dashboard. Tiếp đó nhấn vào **Server Management** -> **Rules**.

Nhấn **Custom Rules** -> **Add new rules file**. Nhập nội dung rule bên dưới vào file, sau đó nhấn **Save** để lưu lại.

### 1.2 Nội Dung Custom Rule

```xml
<group name="windows,sysmon,command_shell,">

    <rule id="100802" level="9">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\cmd\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)\.(bat|cmd)\b</field>
        <description>T1059.003 - Batch or CMD script executed through Windows Command Shell</description>
        <mitre><id>T1059.003</id></mitre>
    </rule>

    <rule id="100801" level="8">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\cmd\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)\s/(c|k|r)\b</field>
        <description>T1059.003 - Command execution using cmd.exe execution switches</description>
        <mitre><id>T1059.003</id></mitre>
    </rule>

    <rule id="100803" level="10">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\cmd\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(powershell|pwsh|wscript|cscript|reg\.exe|schtasks\.exe|certutil\.exe|bitsadmin\.exe)</field>
        <description>T1059.003 - Windows Command Shell launching suspicious utility</description>
        <mitre><id>T1059.003</id></mitre>
    </rule>

</group>
```

### 1.3 Mô Tả Rule

Bộ rule sử dụng **Sysmon Event ID 1 (Process Creation)** để theo dõi `cmd.exe`. Severity tăng khi CMD dùng execution switch (`/c`, `/k`, `/r`), thực thi file `.bat`/`.cmd`, hoặc gọi các utility thường bị lạm dụng như PowerShell, WScript/CScript, `reg.exe`, `schtasks.exe`, `certutil.exe` và `bitsadmin.exe`.

| Rule ID | Level | Kỹ thuật phát hiện |
|---------|-------|--------------------|
| 100801 | 8 | CMD dùng switch `/c`, `/k` hoặc `/r` |
| 100802 | 9 | Thực thi file `.bat` hoặc `.cmd` qua Windows Command Shell |
| 100803 | **10** | CMD gọi PowerShell/WScript/CScript/reg/schtasks/certutil/bitsadmin |

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
Invoke-AtomicTest T1059.003 -GetPrereqs
Invoke-AtomicTest T1059.003
```

## Phase 3: Alert Analysis

### 3.1 Kiểm Tra Alert Trên Wazuh Dashboard

Vào **Threat Hunting** -> tab **Events**, nhập DQL query sau vào thanh tìm kiếm:

```
rule.mitre.id:T1059.003
```

Danh sách alert sẽ hiển thị các rule được kích hoạt trong quá trình chạy Atomic Red Team. Kiểm tra `rule.id`, `rule.level`, `agent.name` và thời gian phát sinh để xác nhận alert đến đúng endpoint thực hiện test.

<img width="1914" height="721" alt="image" src="https://github.com/user-attachments/assets/dc34ecc9-3985-49fd-a585-5844d9d457c7" />

### 3.2 Phân Tích Chi Tiết Alert: Case Study: CMD Launching Suspicious Utility (Rule 100803)

Nhấn vào alert **Rule 100803** nếu test tạo chuỗi `cmd.exe` gọi một utility khác như PowerShell, `reg.exe` hoặc WScript. Đây là pattern thường thấy trong script, malware và hands-on-keyboard activity khi attacker dùng CMD làm launcher cho công cụ tiếp theo.

**Các field cần tập trung khi mở Document Details:**

- `win.eventdata.image`: `cmd.exe`
- `win.eventdata.commandLine` command và utility được gọi
- `win.eventdata.parentImage` process đã launch CMD
- `win.eventdata.parentCommandLine` nếu có

<img width="1100" height="965" alt="image" src="https://github.com/user-attachments/assets/d9b0675e-bd31-4b02-87b8-8b1a04e4da7e" />

**Chuỗi hành vi có thể tái hiện:**

```
Parent Process
  └── cmd.exe /c ...
        └── powershell.exe / reg.exe / schtasks.exe / certutil.exe ...
```

Windows Command Shell xuất hiện rất nhiều trong hệ thống nên detection chỉ dựa vào `cmd.exe` sẽ có false positive cao. Rule 100803 giúp tăng độ ưu tiên khi CMD đóng vai trò launcher cho các utility thường bị attacker lạm dụng.
