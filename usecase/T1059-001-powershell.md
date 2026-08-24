# Use Case - Execution (T1059.001)
## MITRE ATT&CK: Command and Scripting Interpreter - PowerShell

## Phase 1: Chuẩn Bị Rule

### 1.1 Truy cập Rule Management

Đầu tiên bấm vào dấu **3 gạch** trên giao diện Wazuh Dashboard. Tiếp đó nhấn vào **Server Management** -> **Rules**.

Nhấn **Custom Rules** -> **Add new rules file**. Nhập nội dung rule bên dưới vào file, sau đó nhấn **Save** để lưu lại.

### 1.2 Nội Dung Custom Rule

```xml
<group name="windows,sysmon,powershell,">

    <rule id="100601" level="10">
         <if_group>sysmon_event1</if_group>
         <field name="win.eventdata.commandLine" type="pcre2">(?i)(-exec(utionpolicy)?\s+bypass|-noprofile|-nop\b|-windowstyle\s+hidden|-w\s+hidden)</field>
         <description>T1059.001 - Suspicious PowerShell execution options</description>
         <mitre><id>T1059.001</id></mitre>
    </rule>

    <rule id="100602" level="11">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(-encodedcommand|-enc\b|-e\s+[A-Za-z0-9+/=]{20,}|FromBase64String|EncodedArguments)</field>
        <description>T1059.001 - PowerShell encoded or Base64 command execution</description>
        <mitre><id>T1059.001</id></mitre>
    </rule>

    <rule id="100603" level="11">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(\bIEX\b|Invoke-Expression)</field>
        <description>T1059.001 - PowerShell dynamic command execution</description>
        <mitre><id>T1059.001</id></mitre>
    </rule>

    <rule id="100604" level="12">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(DownloadString|WebClient|Invoke-WebRequest|ServerXmlHttp|https?://)</field>
        <description>T1059.001 - PowerShell remote content download detected</description>
        <mitre><id>T1059.001</id></mitre>
    </rule>

    <rule id="100605" level="9">
        <if_group>sysmon_event1</if_group>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)(powershell|pwsh)(\.exe)?</field>
        <description>T1059.001 - PowerShell launched through Windows command shell</description>
        <mitre><id>T1059.001</id></mitre>
    </rule>

</group>
```

### 1.3 Mô Tả Rule

Bộ rule sử dụng **Sysmon Event ID 1 (Process Creation)** và tập trung phân tích `win.eventdata.commandLine`. Rule không cảnh báo mọi lần PowerShell được mở; severity tăng khi command line có các dấu hiệu đáng ngờ như execution policy bypass/hidden window, encoded hoặc Base64 command, `IEX`/`Invoke-Expression`, tải nội dung từ HTTP/HTTPS hoặc xuất hiện chuỗi `powershell`/`pwsh` trong command line.

| Rule ID | Level | Kỹ thuật phát hiện |
|---------|-------|--------------------|
| 100601 | 10 | Execution options đáng ngờ: `ExecutionPolicy Bypass`, `-nop`, `-noprofile`, hidden window |
| 100602 | 11 | Encoded/Base64 PowerShell: `-EncodedCommand`, `-enc`, `FromBase64String`... |
| 100603 | 11 | Dynamic execution qua `IEX` / `Invoke-Expression` |
| 100604 | **12** | Dấu hiệu tải nội dung từ xa: `DownloadString`, `WebClient`, `Invoke-WebRequest`, `ServerXmlHttp`, URL HTTP/HTTPS |
| 100605 | 9 | `commandLine` chứa `powershell`/`pwsh`, dùng để phát hiện PowerShell được gọi qua command shell |

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
Invoke-AtomicTest T1059.001 -GetPrereqs
Invoke-AtomicTest T1059.001
```

## Phase 3: Alert Analysis

### 3.1 Kiểm Tra Alert Trên Wazuh Dashboard

Vào **Threat Hunting** -> tab **Events**, nhập DQL query sau vào thanh tìm kiếm:

```
rule.mitre.id:T1059.001
```

Danh sách alert sẽ hiển thị các rule được kích hoạt trong quá trình chạy Atomic Red Team. Kiểm tra `rule.id`, `rule.level`, `agent.name` và thời gian phát sinh để xác nhận alert đến đúng endpoint thực hiện test.

<img width="1909" height="963" alt="image" src="https://github.com/user-attachments/assets/101dd4d6-6872-4233-a3ac-4f1b5f187814" />

### 3.2 Phân Tích Chi Tiết Alert: Case Study: Encoded PowerShell Command (Rule 100602)

Nhấn vào alert **Rule 100602** nếu Atomic Red Team tạo PowerShell encoded command. Encoded command thường được attacker sử dụng để làm khó việc đọc payload trực tiếp trong command line và né các detection đơn giản.

**Các field cần tập trung khi mở Document Details:**

- `win.eventdata.image`: xác nhận process thực thi (thường là `powershell.exe` hoặc `pwsh.exe`)
- `win.eventdata.commandLine`: `-EncodedCommand`, `-enc`, `-e` Base64 string
- `win.eventdata.parentImage` process gọi PowerShell
- `win.eventdata.user` tài khoản thực thi

<img width="1212" height="960" alt="image" src="https://github.com/user-attachments/assets/a5251997-e4b8-45f4-8782-cd64fb31354e" />

**Chuỗi hành vi có thể tái hiện:**

```
Parent Process
  └── powershell.exe -EncodedCommand <Base64>
        └── Decode / execute PowerShell payload
```

PowerShell là công cụ quản trị hợp lệ nhưng cũng là **LOLBin** rất phổ biến. Các dấu hiệu như encoded command, `IEX`, hidden window hoặc tải nội dung từ xa có giá trị phát hiện cao hơn so với chỉ quan sát việc PowerShell được mở.
