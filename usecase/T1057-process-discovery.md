# Use Case - Discovery (T1057)
## MITRE ATT&CK: Process Discovery

## Phase 1: Chuẩn Bị Rule

### 1.1 Truy cập Rule Management

Đầu tiên bấm vào dấu **3 gạch** trên giao diện Wazuh Dashboard. Tiếp đó nhấn vào **Server Management** -> **Rules**.

Nhấn **Custom Rules** -> **Add new rules file**. Nhập nội dung rule bên dưới vào file, sau đó nhấn **Save** để lưu lại.

### 1.2 Nội Dung Custom Rule

```xml
<group name="windows,sysmon,process_discovery,">

    <rule id="100901" level="6">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\tasklist\.exe$</field>
        <description>T1057 - Process Discovery using tasklist.exe</description>
        <mitre><id>T1057</id></mitre>
    </rule>

    <rule id="100902" level="7">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)\bGet-Process\b</field>
        <description>T1057 - Process Discovery using PowerShell Get-Process</description>
        <mitre><id>T1057</id></mitre>
    </rule>

    <rule id="100903" level="7">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)\bwmic\s+process\b</field>
        <description>T1057 - Process Discovery using WMIC</description>
        <mitre><id>T1057</id></mitre>
    </rule>

    <rule id="100904" level="10">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(tasklist|Get-Process).*(lsass|winlogon|explorer|csrss)</field>
        <description>T1057 - Process Discovery targeting security-sensitive process</description>
        <mitre><id>T1057</id></mitre>
    </rule>

    <rule id="100905" level="7">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\(PCHunter64|ProcessHacker)\.exe$</field>
        <description>T1057 - Process discovery utility execution detected</description>
        <mitre><id>T1057</id></mitre>
    </rule>

</group>
```

### 1.3 Mô Tả Rule

Các rule dựa trên **Sysmon Event ID 1** để phát hiện công cụ liệt kê process như `tasklist`, `Get-Process`, `wmic process`, Process Hacker/PCHunter. Rule 100904 có level cao hơn khi command tập trung vào các process nhạy cảm như `lsass`, `winlogon`, `explorer` hoặc `csrss`.

| Rule ID | Level | Kỹ thuật phát hiện |
|---------|-------|--------------------|
| 100901 | 6 | Process Discovery bằng `tasklist.exe` |
| 100902 | 7 | PowerShell `Get-Process` |
| 100903 | 7 | `wmic process` |
| 100904 | **10** | `tasklist`/`Get-Process` nhắm tới `lsass`, `winlogon`, `explorer`, `csrss` |
| 100905 | 7 | Thực thi `PCHunter64.exe` hoặc `ProcessHacker.exe` |

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
Invoke-AtomicTest T1057 -GetPrereqs
Invoke-AtomicTest T1057
```

## Phase 3: Alert Analysis

### 3.1 Kiểm Tra Alert Trên Wazuh Dashboard

Vào **Threat Hunting** -> tab **Events**, nhập DQL query sau vào thanh tìm kiếm:

```
rule.mitre.id:T1057
```

Danh sách alert sẽ hiển thị các rule được kích hoạt trong quá trình chạy Atomic Red Team. Kiểm tra `rule.id`, `rule.level`, `agent.name` và thời gian phát sinh để xác nhận alert đến đúng endpoint thực hiện test.

<img width="1911" height="853" alt="image" src="https://github.com/user-attachments/assets/9f974c68-7d8b-49a9-83ca-5112e012b42d" />

### 3.2 Phân Tích Chi Tiết Alert: Case Study: Process Discovery bằng tasklist.exe (Rule 100901)

Nhấn vào alert **Rule 100901** để kiểm tra việc thực thi `tasklist.exe`. Đây là một trong những cách đơn giản nhất để attacker khảo sát các process đang chạy trước khi chọn mục tiêu cho credential dumping, injection hoặc defense evasion.

**Các field cần tập trung khi mở Document Details:**

- `win.eventdata.image`: `tasklist.exe`
- `win.eventdata.parentCommandLine` 
- `win.eventdata.parentImage` tiến trình gọi tasklist
- `win.eventdata.user` tài khoản thực hiện discovery

<img width="1220" height="964" alt="image" src="https://github.com/user-attachments/assets/119f63e1-3d51-47a6-9558-03f00fb79fa1" />

**Chuỗi hành vi có thể tái hiện:**

```
powershell.exe / cmd.exe
  └── tasklist.exe
        └── Liệt kê các process đang chạy trên endpoint
```

Process Discovery có thể xuất hiện trong hoạt động quản trị bình thường, do đó alert nên được correlation với parent process và các hành vi kế tiếp. Nếu sau `tasklist` xuất hiện LSASS access hoặc process injection thì mức độ nghi ngờ tăng đáng kể.
