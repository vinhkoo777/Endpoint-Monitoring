# Endpoint Monitoring (Sysmon + Wazuh)

> Lab giám sát và phát hiện hành vi tấn công trên Windows sử dụng **Sysmon**, **Wazuh**, **MITRE ATT&CK** và **Atomic Red Team**.

## Tổng quan

Project tập trung xây dựng và kiểm thử các rule phát hiện hành vi đáng ngờ trên Windows.

* **Sysmon**: ghi nhận sự kiện trên endpoint.
* **Wazuh**: thu thập, phân tích log và sinh cảnh báo.
* **Atomic Red Team**: mô phỏng các kỹ thuật tấn công theo MITRE ATT&CK.
* **Custom Rules**: phát hiện các hành vi tấn công dựa trên log Sysmon.

## Các kỹ thuật đã triển khai

| MITRE ATT&CK | Kỹ thuật                            | Rule                                                 |
| ------------ | ----------------------------------- | ---------------------------------------------------- |
| T1003.001    | OS Credential Dumping: LSASS Memory | [`XML`](./rules/T1003-001-lsass-memory.xml)          |
| T1033        | System Owner/User Discovery         | [`XML`](./rules/T1033-user-discovery.xml)            |
| T1053.005    | Scheduled Task/Job: Scheduled Task  | [`XML`](./rules/T1053-005-scheduled-task.xml)        |
| T1055        | Process Injection                   | [`XML`](./rules/T1055-process-injection.xml)         |
| T1057        | Process Discovery                   | [`XML`](./rules/T1057-process-discovery.xml)         |
| T1059.001    | PowerShell                          | [`XML`](./rules/T1059-001-powershell.xml)            |
| T1059.003    | Windows Command Shell               | [`XML`](./rules/T1059-003-windows-command-shell.xml) |
| T1547.001    | Registry Run Keys / Startup Folder  | [`XML`](./rules/T1547-001-registry-run-keys.xml)     |


## Cài đặt

Xem [`setup.md`](./setup.md) để cài đặt và cấu hình môi trường lab.

---

> Make by **K0g4** with love <333
