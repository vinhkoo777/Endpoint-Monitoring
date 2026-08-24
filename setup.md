# Setup Wazuh Lab

Trong phần này, tôi sẽ hướng dẫn quá trình xây dựng một mô hình Wazuh Lab cơ bản trên môi trường máy ảo. Lab sẽ bao gồm một máy Ubuntu Server dùng để cài đặt Wazuh Server và một máy Windows 11 dùng làm endpoint để cài Wazuh Agent.

Sau khi hoàn tất phần setup, tôi sẽ tiếp tục cấu hình môi trường để thu thập log từ endpoint, đồng thời cài đặt Atomic Red Team nhằm mô phỏng một số hành vi tấn công theo MITRE ATT&CK. Mục tiêu của lab là tạo ra log tấn công có chủ đích, từ đó kiểm tra khả năng ghi nhận, phân tích và cảnh báo của Wazuh/SIEM.

## Phase 1: Thiết lập cấu trúc máy ảo

Lab sử dụng VMware Workstation để chạy các máy ảo. Có thể thay thế bằng VirtualBox hoặc KVM tùy theo môi trường triển khai.

### Các máy ảo sử dụng 

Môi trường lab gồm hai máy ảo:
- Ubuntu Server 24.04.4: cài đặt Wazuh Server.
- Windows 11: cài đặt Wazuh Agent.

Nên tạo một thư mục riêng để quản lý các máy ảo. Trong VMware Workstation có thể chọn **chuột phải -> New Folder**.

<img width="336" height="323" alt="image" src="https://github.com/user-attachments/assets/0979b19b-7217-4346-9e85-ba32bf3347fb" />

Ví dụ cách sắp xếp các máy ảo trong lab:

<img width="248" height="81" alt="image" src="https://github.com/user-attachments/assets/93390915-98d6-418b-9e79-34a9451232e2" />

> **Lưu ý:** Tài liệu giả định các máy ảo đã được tạo sẵn và tập trung vào quá trình cài đặt Wazuh Server, Wazuh Agent và môi trường mô phỏng.

### Bảng IP các máy ảo

| STT | Tên Máy       | IP      | 
|-----|---------------|-----------------|
| 1   | Windows Client     | 192.168.15.135   | 
| 2   | Wazuh     | 192.168.15.134    | 

## Phase 2: Cài đặt Wazuh 

Cài đặt Wazuh bằng lệnh sau:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Sau khi cài đặt hoàn tất, terminal sẽ hiển thị thông tin truy cập Wazuh Dashboard:

```bash
INFO: --- Summary ---
INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>
    User: admin
    Password: <ADMIN_PASSWORD>
INFO: Installation finished.
```

Truy cập Wazuh Dashboard tại:

```
https://<WAZUH_DASHBOARD_IP_ADDRESS>
```

Sử dụng tài khoản được tạo trong quá trình cài đặt:
  
- User: admin
- Password: <ADMIN_PASSWORD>

## Phase 3: Setup Wazuh Agent

Truy cập Wazuh Dashboard, đăng nhập bằng tài khoản quản trị và chọn **Deploy new agent**.

<img width="1907" height="963" alt="image" src="https://github.com/user-attachments/assets/40454e00-2173-450e-86d4-a0137d632154" />

Chọn **Windows**. Tại **Server address**, nhập địa chỉ của máy Ubuntu Server (`192.168.15.134`) và đặt tên agent, ví dụ `Windows`.

<img width="1910" height="965" alt="image" src="https://github.com/user-attachments/assets/32a5a7d8-02d0-4fd8-a53a-970f16eaca95" />

Trên Windows, thực thi các lệnh được Wazuh Dashboard cung cấp để cài đặt và đăng ký agent.

<img width="1899" height="746" alt="image" src="https://github.com/user-attachments/assets/8aa48b6a-0709-45c2-a8a3-43c4b2e3edac" />

<img width="961" height="494" alt="image" src="https://github.com/user-attachments/assets/bcc18e4a-fa21-4386-8608-b9a1fada13ca" />

Sau khi hoàn tất, chọn **Back to agent list**.

<img width="1897" height="196" alt="image" src="https://github.com/user-attachments/assets/d2571224-d2f9-43bc-87cd-2f65191fc541" />

Agent Windows sẽ xuất hiện trong danh sách endpoint của Wazuh.

<img width="1909" height="963" alt="image" src="https://github.com/user-attachments/assets/8ca13099-aa4c-4f78-bf0f-1d271afdd0af" />

## Phase 4: Cài đặt Atomic Red Team

Ở phase này, trên máy lab ta sẽ cài đặt Atomic Red Team để mô phỏng các kỹ thuật tấn công theo MITRE ATT&CK.

> Atomic Red Team là bộ test case mã nguồn mở, trong đó mỗi test đại diện cho một hành vi tấn công nhỏ, độc lập và dễ kiểm soát. Công cụ này giúp tạo log tấn công có chủ đích để kiểm tra khả năng ghi nhận và phát hiện của Sysmon, Windows Event Log, Wazuh/SIEM. 

Trên Windows, mở **PowerShell** với quyền **Administrator** và thực hiện các bước bên dưới.

> **Cảnh báo:** Các thao tác vô hiệu hóa hoặc thêm exclusion cho Microsoft Defender chỉ nên thực hiện trên **máy ảo lab cô lập**, không áp dụng trên máy thật hoặc hệ thống production.

**Bước 1:** Cấu hình exclusion và tạm thời vô hiệu hóa một số thành phần Microsoft Defender để tránh làm gián đoạn Atomic Red Team trong môi trường lab.

```
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
Add-MpPreference -ExclusionPath "C:\Tools"
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
```
<img width="646" height="95" alt="image" src="https://github.com/user-attachments/assets/68b0a4f0-8cee-4c69-a12b-4c7eb7acfb25" />

Nếu cần cho bài test trong lab, mở **Windows Security** từ khay hệ thống để kiểm tra các thiết lập bảo vệ liên quan.

<img width="795" height="435" alt="image" src="https://github.com/user-attachments/assets/0ce6942e-95bd-4f7c-9b95-5cd5c9eeb746" />

Chọn **Virus & threat protection**.

<img width="1587" height="911" alt="image" src="https://github.com/user-attachments/assets/c788ee89-aa4b-46c5-859d-11583df04c6b" />

Trong **Virus & threat protection settings**, chọn **Manage settings** và chỉ tạm thời vô hiệu hóa các tùy chọn cần thiết cho bài test trong máy ảo lab.

<img width="697" height="905" alt="image" src="https://github.com/user-attachments/assets/54668c0e-8226-4e63-8913-d8cdcfe1a35e" />

<img width="868" height="783" alt="image" src="https://github.com/user-attachments/assets/96ac2e99-3e3c-4422-b78e-3bd67574a2e6" />

**Bước 2:** Cho phép thực thi script trong môi trường lab
```
Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
```

**Bước 3:** Cài đặt Atomic Red Team
```
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

<img width="966" height="190" alt="image" src="https://github.com/user-attachments/assets/a92cf2ef-85ee-48fb-a8fb-4090d0fd15cf" />

Nhấn **Enter** để tiếp tục quá trình cài đặt.
