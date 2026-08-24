# Use Case - Defense Evasion / Privilege Escalation (T1055)
## MITRE ATT&CK: Process Injection

## Phase 1: Chuẩn Bị Rule

### 1.1 Truy cập Rule Management

Đầu tiên bấm vào dấu **3 gạch** trên giao diện Wazuh Dashboard. Tiếp đó nhấn vào **Server Management** -> **Rules**.

Nhấn **Custom Rules** -> **Add new rules file**. Nhập nội dung rule bên dưới vào file, sau đó nhấn **Save** để lưu lại.

### 1.2 Nội Dung Custom Rule

```xml
<group name="windows,sysmon,process_injection,">

    <rule id="100701" level="12">
        <if_group>sysmon_event8</if_group>
        <field name="win.eventdata.sourceImage" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
        <description>T1055 - PowerShell created a remote thread in another process</description>
        <mitre><id>T1055</id></mitre>
    </rule>

    <rule id="100702" level="12">
        <if_group>sysmon_event8</if_group>
        <field name="win.system.message" type="pcre2">(?i)StartModule:\s*-</field>
        <description>T1055 - Remote thread created with no identifiable start module</description>
        <mitre><id>T1055</id></mitre>
    </rule>

    <rule id="100703" level="10">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\(CreateRemoteThread|CreateRemoteThreadNative|InjectView|redVanity|RWXinjectionLocal|uuid_injection)\.exe$</field>
        <description>T1055 - Process injection utility execution detected</description>
        <mitre><id>T1055</id></mitre>
    </rule>

    <rule id="100704" level="11">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(CreateRemoteThread|CreateRemoteThreadNative|InjectView|redVanity|RWXinjectionLocal|uuid_injection)</field>
        <description>T1055 - PowerShell launching process injection utility</description>
        <mitre><id>T1055</id></mitre>
    </rule>

</group>
```

### 1.3 Mô Tả Rule

Rule sử dụng **Sysmon Event ID 8 (CreateRemoteThread)** để phát hiện PowerShell tạo remote thread vào process khác hoặc trường hợp remote thread không xác định được `StartModule`. Đồng thời sử dụng **Event ID 1 (Process Creation)** để phát hiện các utility và command line liên quan đến process injection.

| Rule ID | Level | Kỹ thuật phát hiện |
|---------|-------|--------------------|
| 100701 | **12** | PowerShell/Pwsh tạo remote thread vào process khác |
| 100702 | **12** | Remote thread không xác định được `StartModule` |
| 100703 | 10 | Phát hiện utility process injection như `InjectView`, `redVanity`, `uuid_injection`... |
| 100704 | 11 | PowerShell khởi chạy utility liên quan process injection |

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
Invoke-AtomicTest T1055 -GetPrereqs
Invoke-AtomicTest T1055
```

## Phase 3: Alert Analysis

### 3.1 Kiểm Tra Alert Trên Wazuh Dashboard

Vào **Threat Hunting** -> tab **Events**, nhập DQL query sau vào thanh tìm kiếm:

```text
rule.mitre.id:T1055
```

<img width="1917" height="521" alt="image" src="https://github.com/user-attachments/assets/9d55b570-a829-4e37-83f4-df6c21909788" />

Danh sách alert sẽ hiển thị các rule được kích hoạt trong quá trình chạy Atomic Red Team. Kiểm tra `rule.id`, `rule.level`, `agent.name` và thời gian phát sinh để xác nhận alert đến đúng endpoint thực hiện test.

<img width="1908" height="962" alt="image" src="https://github.com/user-attachments/assets/1ef779f8-e59c-4dbd-ab05-3ecd32492c03" />

### 3.2 Phân Tích Chi Tiết Alert: Case Study: PowerShell CreateRemoteThread (Rule 100701)

Nhấn vào alert **Rule 100701** để kiểm tra **Sysmon Event ID 8**. Rule được kích hoạt khi PowerShell hoặc Pwsh tạo remote thread trong một process khác, đây là telemetry quan trọng khi điều tra hành vi Process Injection.

**Các field cần tập trung khi mở Document Details:**

- `win.eventdata.sourceImage` process thực hiện tạo remote thread
- `win.eventdata.targetImage` process nhận remote thread
- `win.eventdata.sourceProcessId` / `targetProcessId`
- `win.eventdata.newThreadId`
- `win.eventdata.startAddress`
- `win.system.message` để kiểm tra `StartModule` và `StartFunction`

<img width="1131" height="967" alt="image" src="https://github.com/user-attachments/assets/a0f87e07-186f-4a84-a7ee-f14bf4049008" />

**Chuỗi hành vi có thể tái hiện:**

```text
PowerShell
  └── CreateRemoteThread
        └── Target Process
              └── Remote thread bắt đầu thực thi trong target process
```

Process Injection thường được malware sử dụng để **thực thi code bên trong process khác**, hỗ trợ né tránh detection hoặc tận dụng context của target process. Alert cần được ưu tiên điều tra khi source/target process bất thường hoặc `StartModule` không xác định.
