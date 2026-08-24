# Use Case - Persistence (T1053.005)
## MITRE ATT&CK: Scheduled Task/Job - Scheduled Task

## Phase 1: Chuẩn Bị Rule

### 1.1 Truy cập Rule Management

Đầu tiên bấm vào dấu **3 gạch** trên giao diện Wazuh Dashboard. Tiếp đó nhấn vào **Server Management** -> **Rules**.

Nhấn **Custom Rules** -> **Add new rules file**. Nhập nội dung rule bên dưới vào file, sau đó nhấn **Save** để lưu lại.

### 1.2 Nội Dung Custom Rule

```xml
<group name="windows,sysmon,scheduled_task,">

    <rule id="100501" level="10">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(/create|/change)</field>
        <description>T1053.005 - Scheduled Task creation/modification using schtasks.exe</description>
        <mitre><id>T1053.005</id></mitre>
    </rule>

    <rule id="100502" level="10">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(New-ScheduledTask|Register-ScheduledTask|Set-ScheduledTask|New-ScheduledTaskAction|New-ScheduledTaskTrigger)</field>
        <description>T1053.005 - Scheduled Task created or modified using PowerShell</description>
        <mitre><id>T1053.005</id></mitre>
    </rule>

    <rule id="100503" level="8">
        <if_group>sysmon_event_11</if_group>
        <field name="win.eventdata.targetFilename" type="pcre2">(?i)^C:\\\\Windows\\\\System32\\\\Tasks\\\\</field>
        <description>T1053.005 - Scheduled Task file created in Windows Task Scheduler directory</description>
        <mitre><id>T1053.005</id></mitre>
    </rule>

    <rule id="100504" level="12">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)/create</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(powershell|cmd\.exe|IEX|FromBase64String|EncodedCommand|-enc)</field>
        <description>T1053.005 - Suspicious Scheduled Task executing command interpreter or PowerShell</description>
        <mitre><id>T1053.005</id></mitre>
    </rule>

</group>
```

### 1.3 Mô Tả Rule

Rule sử dụng **Sysmon Event ID 1** để phát hiện `schtasks.exe`/PowerShell tạo hoặc chỉnh sửa Scheduled Task và **Sysmon Event ID 11** để phát hiện file task được tạo dưới `C:\Windows\System32\Tasks`. Rule 100504 có level cao nhất do task được cấu hình để chạy command interpreter hoặc PowerShell.

| Rule ID | Level | Kỹ thuật phát hiện |
|---------|-------|--------------------|
| 100501 | 10 | `schtasks.exe` với `/create` hoặc `/change` |
| 100502 | 10 | PowerShell dùng `New-ScheduledTask`, `Register-ScheduledTask`, `Set-ScheduledTask`... |
| 100503 | 8 | File task mới được tạo trong `C:\Windows\System32\Tasks\` |
| 100504 | **12** | `schtasks /create` chạy PowerShell/CMD hoặc chứa dấu hiệu encoded command |

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
Invoke-AtomicTest T1053.005 -GetPrereqs
Invoke-AtomicTest T1053.005
```

## Phase 3: Alert Analysis

### 3.1 Kiểm Tra Alert Trên Wazuh Dashboard

Vào **Threat Hunting** -> tab **Events**, nhập DQL query sau vào thanh tìm kiếm:

```
rule.mitre.id:T1053.005
```

<img width="1912" height="353" alt="image" src="https://github.com/user-attachments/assets/b99fce0f-3f4c-46a4-9ec7-e3ad0682aeff" />

Danh sách alert sẽ hiển thị các rule được kích hoạt trong quá trình chạy Atomic Red Team. Kiểm tra `rule.id`, `rule.level`, `agent.name` và thời gian phát sinh để xác nhận alert đến đúng endpoint thực hiện test.

<img width="1919" height="920" alt="image" src="https://github.com/user-attachments/assets/95d6ede6-ec62-412f-9be2-aba1afbfacc4" />

### 3.2 Phân Tích Chi Tiết Alert: Case Study: Scheduled Task Creation bằng schtasks.exe (Rule 100501)

Nhấn vào alert **Rule 100501** để kiểm tra hành vi tạo Scheduled Task bằng `schtasks.exe`. Scheduled Task thường bị lạm dụng để duy trì persistence hoặc thực thi payload theo thời gian định sẵn.

**Các field cần tập trung khi mở Document Details:**

- `win.eventdata.image` `schtasks.exe`
- `win.eventdata.commandLine` tên task, trigger và action được cấu hình
- `win.eventdata.parentImage` tiến trình khởi tạo `schtasks.exe`
- Nếu có Rule 100503: `win.eventdata.targetFilename` file task được tạo

<img width="1156" height="975" alt="image" src="https://github.com/user-attachments/assets/0702ca49-090a-47ec-9f6e-0ff807ece165" />

<img width="1105" height="932" alt="image" src="https://github.com/user-attachments/assets/543d0842-fb8f-4501-aa74-9c755a5e5886" />

**Chuỗi hành vi có thể tái hiện:**

```
powershell.exe / cmd.exe
  └── schtasks.exe /create ...
        └── Windows Task Scheduler
              └── Thực thi payload theo trigger đã cấu hình
```

Scheduled Task là cơ chế hợp lệ của Windows nhưng thường bị lạm dụng cho **Persistence**. Khi triage nên kiểm tra tên task, action thực thi, tài khoản chạy task và parent process để phân biệt hoạt động quản trị hợp lệ với hành vi đáng ngờ.
