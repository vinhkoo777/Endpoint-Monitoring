# Use Case - Persistence (T1547.001)
## MITRE ATT&CK: Boot or Logon Autostart Execution - Registry Run Keys / Startup Folder

## Phase 1: Chuẩn Bị Rule

### 1.1 Truy cập Rule Management

Đầu tiên bấm vào dấu **3 gạch** trên giao diện Wazuh Dashboard. Tiếp đó nhấn vào **Server Management** -> **Rules**.

<img width="1911" height="968" alt="image" src="https://github.com/user-attachments/assets/c9d6b110-c660-4e42-a4d6-91c3b53464a9" />

Nhấn **Custom Rules** -> **Add new rules file**. Nhập nội dung rule bên dưới vào file, sau đó nhấn **Save** để lưu lại.

<img width="1912" height="967" alt="image" src="https://github.com/user-attachments/assets/cb357b4c-f307-4749-a79c-3399baff6e06" />

<img width="1908" height="958" alt="image" src="https://github.com/user-attachments/assets/c7d15b03-83cc-4964-9285-711d8bbf6bc8" />

Sau cùng là nhấn **reload**.

### 1.2 Nội Dung Custom Rule

```xml
<group name="sysmon,windows,sysmon_event_13,persistence,">

  <rule id="40000" level="7">
    <if_group>sysmon_eid13_detections</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)HKU\\\\.*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\.*</field>
    <description>T1547.001 - Registry Run Key Persistence - HKCU/HKU</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="40010" level="8">
    <if_group>sysmon_eid13_detections</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce(Ex)?\\\\.*</field>
    <description>T1547.001 - Registry RunOnce / RunOnceEx Persistence</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="40030" level="14">
    <if_group>sysmon_eid13_detections</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)HKU\\\\.*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\socks5_powershell</field>
    <description>T1547.001 - SystemBC-like Registry Run Key Persistence</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="40080" level="8">
    <if_group>sysmon_eid13_detections</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\.*</field>
    <description>T1547.001 - Secedit-created HKLM Run Key Persistence</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

</group>

<group name="sysmon,windows,sysmon_event_11,persistence,">

  <rule id="40140" level="7">
    <if_group>sysmon_eid11_detections</if_group>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\.+\.(bat|cmd|jse|js|vbs|vbe|lnk|exe|ps1)</field>
    <description>T1547.001 - File Created in Common Startup Folder</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="40150" level="7">
    <if_group>sysmon_eid11_detections</if_group>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\.+\.(bat|cmd|jse|js|vbs|vbe|lnk|exe|ps1)</field>
    <description>T1547.001 - File Created in User Startup Folder</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

</group>
```

### 1.3 Mô Tả Rule
 
Rule được chia thành 2 nhóm dựa trên Sysmon Event ID:
 
**Nhóm 1: Sysmon Event ID 13 (RegistryValueSet):** Phát hiện hành vi ghi/sửa registry key liên quan đến persistence.
 
| Rule ID | Level | Kỹ thuật phát hiện |
|---------|-------|--------------------|
| 40000 | 7 | `HKU\...\CurrentVersion\Run\*` — HKCU Run key |
| 40010 | 8 | `\CurrentVersion\RunOnce` hoặc `RunOnceEx\*` |
| 40030 | **14** | `HKU\...\Run\socks5_powershell` — SystemBC RAT IOC |
| 40080 | 8 | `HKLM\...\CurrentVersion\Run\*` — HKLM Run key |
 
**Nhóm 2: Sysmon Event ID 11 (FileCreate):** Phát hiện file được tạo trong thư mục Startup.
 
| Rule ID | Level | Kỹ thuật phát hiện |
|---------|-------|--------------------|
| 40140 | 7 | File `.bat/.cmd/.jse/.js/.vbs/.vbe/.lnk/.exe/.ps1` trong `ProgramData\...\Startup` |
| 40150 | 7 | File `.bat/.cmd/.jse/.js/.vbs/.vbe/.lnk/.exe/.ps1` trong `AppData\...\Startup` |
 
> **Lưu ý:** Rule 40030 (SystemBC RAT IOC) được đặt level **14** do đây là IOC cụ thể của malware đã biết key name `socks5_powershell` là chỉ dấu trực tiếp của SystemBC RAT, không phải hành vi generic.

### 1.4 Reload và Restart Service

Sau khi lưu rule, nhấn **Reload** trên giao diện Wazuh Dashboard.

Trên máy **Ubuntu Server**, restart Wazuh Manager để áp dụng rule:

```bash
sudo systemctl restart wazuh-manager
```

## Phase 2: Thực Hiện Test (Atomic Red Team)

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Invoke-AtomicTest T1547.001 -GetPrereqs
Invoke-AtomicTest T1547.001
```
 
## Phase 3: Alert Analysis
 
### 3.1 Kiểm Tra Alert Trên Wazuh Dashboard
 
Vào **Threat Hunting** -> tab **Events**, nhập DQL query sau vào thanh tìm kiếm:
 
```
rule.mitre.id:T1547.001
```
 
<img width="1899" height="410" alt="image" src="https://github.com/user-attachments/assets/dd08eb64-5a8c-451f-9309-84d821f5ea04" />
Danh sách alert ghi nhận các rule đã được kích hoạt:
 
<img width="1903" height="409" alt="image" src="https://github.com/user-attachments/assets/8f57a4fb-2815-4ac7-8a56-174adbb7f69a" />
Tất cả alert đều đến từ agent windows đúng với máy thực hiện test.
 
### 3.2 Phân Tích Chi Tiết Alert: Case Study: Registry Run Key via reg.exe (Rule 40000)
 
Nhấn vào alert **Rule 40000** (level 7) để mở **Document Details**. Alert này ghi nhận hành vi ghi vào `HKCU\...\CurrentVersion\Run` thông qua tiến trình `reg.exe`  kỹ thuật persistence phổ biến nhất trong nhóm Registry Run Keys.
 
**Thông tin registry activity thu thập được từ Sysmon Event ID 13:**

<img width="955" height="914" alt="Screenshot 2026-05-21 182120" src="https://github.com/user-attachments/assets/aa2dea1d-e91c-4b83-a51b-e84eeed3a7c2" />
 
**Registry Persistence Chain tái hiện được:**
 
```
reg.exe (PID: 4372)                     <- Atomic Red Team launcher
  └── SetValue (Sysmon EID 13)
        └── HKU\S-1-5-21-...\Run\Atomic Red Team
              └── Value: "C:\Path\AtomicRedTeam.exe"
                    └── Trigger: mỗi lần user logon -> payload tự động chạy
```
 
Kỹ thuật này sử dụng `reg.exe` công cụ dòng lệnh built-in của Windows để ghi payload vào Run key dưới hive `HKU` của user hiện tại. Payload `AtomicRedTeam.exe` sẽ được Windows tự động khởi chạy mỗi khi người dùng đăng nhập mà không cần bất kỳ đặc quyền administrator nào, khiến đây là một trong những vector persistence phổ biến và khó phát hiện nhất.

