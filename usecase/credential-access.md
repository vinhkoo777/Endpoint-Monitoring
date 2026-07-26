# Use Case - Credential Access (T1003.001)
## MITRE ATT&CK: OS Credential Dumping - LSASS Memory

## Phase 1: Chuẩn Bị Rule

### 1.1 Truy cập Rule Management

Đầu tiên bấm vào dấu **3 gạch** trên giao diện Wazuh Dashboard. Tiếp đó nhấn vào **Server Management** -> **Rules**.

<img width="1914" height="966" alt="image" src="https://github.com/user-attachments/assets/4f6b595d-27de-4d89-b0cd-4a37a759d929" />

Nhấn **Custom Rules** -> **Add new rules file**. Nhập nội dung rule bên dưới vào file, sau đó nhấn **Save** để lưu lại.

<img width="1906" height="924" alt="image" src="https://github.com/user-attachments/assets/fff6713e-fa0b-4435-8480-08934c6c8ec7" />

<img width="1910" height="963" alt="image" src="https://github.com/user-attachments/assets/a775424d-dfbe-41a7-a387-d77cf55e5d45" />

### 1.2 Nội Dung Custom Rule

```xml
<group name="sysmon_event1,windows,sysmon,">
  
  <rule id="30000" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)procdump(?:64)?\.exe.*lsass(?:\.exe)?.*</field>
    <description>T1003.001 - Dump LSASS.exe Memory using ProcDump </description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <rule id="30010" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)rundll32\.exe.*comsvcs\.dll,?\s*MiniDump.*\d+.*</field>
    <description>T1003.001 - Dump LSASS.exe Memory using comsvcs.dll</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
  
  <rule id="30020" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)nanodump(?:\.x64)?\.exe.*(-w|--write).*</field>
    <description>T1003.001 - Dump LSASS.exe Memory using NanoDump</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <rule id="30030" level="13">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)mimikatz\.exe.*sekurlsa::.*</field>
    <description>T1003.001 - Offline Credential Theft With Mimikatz</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <rule id="30040" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)rdrleakdiag\.exe.*fullmemdmp.*</field>
    <description>T1003.001 - Dump LSASS.exe using lolbin rdrleakdiag.exe</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
 
  <rule id="30050" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)pypykatz.*live.*lsa.*</field>
    <description>T1003.001 - LSASS read with pypykatz</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
  
  <rule id="30060" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)Outflank-Dumpert\.exe.*</field>
    <description>T1003.001 - LSASS memory dumping using Outflank Dumpert</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <rule id="30070" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)createdump\.exe.*(?:/d|-f|--name|\.dmp|\d+).*</field>
    <description>T1003.001 - LSASS memory dumping using createdump.exe</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <rule id="30080" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)xordump\.exe.*</field>
    <description>T1003.001 - LSASS memory dumping using xordump</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

</group>
```

### 1.3 Mô Tả Rule

Toàn bộ rule thuộc nhóm `sysmon_event1` và được trigger bởi **Sysmon Event ID 1** [Process Creation]. Mỗi rule phát hiện một công cụ credential dumping khác nhau thông qua phân tích `commandLine`:

| Rule ID | Level | Tool | Kỹ thuật phát hiện |
|---------|-------|------|--------------------|
| 30000 | 10 | ProcDump | Regex khớp `procdump[64].exe` kết hợp target `lsass` |
| 30010 | 10 | comsvcs.dll | Phát hiện `rundll32` gọi `MiniDump` qua comsvcs.dll |
| 30020 | 10 | NanoDump | Khớp flag `-w / --write` của NanoDump |
| 30030 | 13 | Mimikatz | Critical severity phát hiện module `sekurlsa::` |
| 30040 | 10 | rdrleakdiag.exe | LOLBin với flag `fullmemdmp` |
| 30050 | 10 | pypykat | Python-based LSA credential reader |
| 30060 | 10 | Outflank Dumpert | Syscall-based LSASS dumper |
| 30070 | 10 | createdump.exe | .NET runtime dump utility bị lạm dụng |
| 30080 | 10 | xordump | XOR-encoded LSASS dump tool |

> **Lưu ý:** Rule 30030 (Mimikatz) được đặt level **13** do mức độ nghiêm trọng cao hơn - Do Mimikatz có khả năng extract plaintext credentials trực tiếp từ bộ nhớ.

### 1.4 Reload và Restart Service

Sau khi lưu rule, nhấn **Reload** trên giao diện Wazuh Dashboard.

Trên máy **Ubuntu Server**, restart Wazuh Manager để áp dụng rule:

```bash
sudo systemctl restart wazuh-manager
```

## Phase 2: Thực Hiện Test (Atomic Red Team)

Trên máy **Windows**, mở **PowerShell** với quyền **Administrator** và chạy các lệnh sau:

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Invoke-AtomicTest T1003.001 -GetPrereqs
Invoke-AtomicTest T1003.001
```

Atomic Red Team sẽ lần lượt thực thi các kỹ thuật dump LSASS được map theo MITRE T1003.001, bao gồm ProcDump, comsvcs.dll MiniDump và các công cụ khác tùy theo prerequisites được cài đặt.

## Phase 3: Alert Analysis

### 3.1 Kiểm Tra Alert Trên Wazuh Dashboard
 
Vào **Threat Hunting** -> tab **Events**, nhập DQL query sau vào thanh tìm kiếm:
 
```
rule.mitre.id:T1003.001
```
 
Kết quả trả về **37 hits** trong khoảng thời gian 24 giờ (May 20–21, 2026). Biểu đồ histogram cho thấy toàn bộ alert tập trung tại thời điểm chạy test/
 
Danh sách alert ghi nhận đầy đủ các rule đã được kích hoạt:
 
<img width="1913" height="961" alt="image" src="https://github.com/user-attachments/assets/da8bf7be-a833-4e34-87c1-207e052968eb" />
 
### 3.2 Phân Tích Chi Tiết Alert: Case Study: Mimikatz (Rule 30030)
 
Nhấn vào alert **Rule 30030** (level 13) để mở **Document Details**. Đây là alert có mức độ nghiêm trọng cao nhất trong test, tương ứng với hành vi credential dumping trực tiếp từ LSASS.

<img width="952" height="913" alt="Screenshot 2026-05-21 172608" src="https://github.com/user-attachments/assets/cf461147-81bc-47c7-aa74-91e6b6e0a05a" />

**Process Tree tái hiện được:**
 
```
powershell.exe (PID: 7752)  <- Parent — Atomic Red Team launcher
  └── cmd.exe               <- Child — thực thi mimikatz
        └── mimikatz.exe    <- Payload — sekurlsa::minidump + logonpasswords
```
 
**Command Line được trigger bởi Rule 30030:**
 
```
mimikatz.exe "sekurlsa::minidump %tmp%\lsass.DMP" "sekurlsa::logonpasswords full" exit
```
 
Mimikatz đọc file dump LSASS tại `%tmp%\lsass.DMP` rồi gọi `sekurlsa::logonpasswords` để extract credentials đây là kỹ thuật offline credential theft điển hình, cho phép đọc hash và plaintext password mà không cần tương tác trực tiếp với process LSASS đang chạy.
 
