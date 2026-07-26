# Set Up Wazuh Lab

Trong phần này, tôi sẽ hướng dẫn quá trình xây dựng một mô hình Wazuh Lab cơ bản trên môi trường máy ảo. Lab sẽ bao gồm một máy Ubuntu Server dùng để cài đặt Wazuh Server và một máy Windows 11 dùng làm endpoint để cài Wazuh Agent.

Sau khi hoàn tất phần setup, tôi sẽ tiếp tục cấu hình môi trường để thu thập log từ endpoint, đồng thời cài đặt Atomic Red Team nhằm mô phỏng một số hành vi tấn công theo MITRE ATT&CK. Mục tiêu của lab là tạo ra log tấn công có chủ đích, từ đó kiểm tra khả năng ghi nhận, phân tích và cảnh báo của Wazuh/SIEM.

## Phase 1: Set Up cấu trúc máy ảo 

Tôi sẽ sử dụng VMWare Workstation để làm phần mềm chạy các máy ảo. Bạn có thể sử dụng virtual box hay kvm tùy vào sở thích.

### Các máy ảo sử dụng 

Ở đây tôi đã có chuẩn bị trước 4 máy ảo 
- Ubuntu Server 24.04.4: Máy này tôi sẽ tiến hành cài Wazuh
- Windows 11 : Tôi sẽ tiến hành cài Wazuh Agent

Nếu được nên tạo 1 folder chứa 4 máy ảo trong đó để dễ dàng quản lí. Cách làm **chuột phải -> New Folder**.

<img width="336" height="323" alt="image" src="https://github.com/user-attachments/assets/0979b19b-7217-4346-9e85-ba32bf3347fb" />

Đây là cách sắp xếp của tôi.

<img width="248" height="81" alt="image" src="https://github.com/user-attachments/assets/93390915-98d6-418b-9e79-34a9451232e2" />

**NOTE: Ở đây tôi đã cài đặt sẳn hết tất cả máy ảo nên chủ yếu `setup.md` để hướng dẫn setup wazuh và các wazuh agent**

### Bảng Ip các máy ảo 

| STT | Tên Máy       | IP      | 
|-----|---------------|-----------------|
| 1   | Windows Client     | 192.168.15.135   | 
| 2   | Wazuh     | 192.168.15.134    | 

## Phase 2: Cài đặt Wazuh 

Đầu tiên cài đặt wazuh bằng dòng lệnh dưới. 

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Sau khi cài xong thì sẽ có thông báo. 

```bash
INFO: --- Summary ---
INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>
    User: admin
    Password: <ADMIN_PASSWORD>
INFO: Installation finished.
```

Và truy cập thông qua. 

```
https://<WAZUH_DASHBOARD_IP_ADDRESS>
```

Sử dụng tại khoản đã được cung cấp ở trên.
  
- User: admin
- Password: <ADMIN_PASSWORD>

## Phase 3: Setup Wazuh Agent

Đầu tiên ta vào truy cập vào địa chỉ Wazuh đã được cấp ở trên. Tiếp đó nhập tài khoản và mật khẩu để đăng nhập. Xong rồi trong màng hình chính ta nhấn vào **Deploy new agent**.

<img width="1907" height="963" alt="image" src="https://github.com/user-attachments/assets/40454e00-2173-450e-86d4-a0137d632154" />

Bước đầu tiên chọn **Windows**. Tiếp đó **Server address** ta sẽ nhập địa chỉ của máy **Ubuntu Server** vào thì đó là `192.168.15.134`. Và tôi sẽ đặt tên Agent là Windows. 

<img width="1910" height="965" alt="image" src="https://github.com/user-attachments/assets/32a5a7d8-02d0-4fd8-a53a-970f16eaca95" />

Tiếp đó trên Windows ta thực hiện 2 đoạn lệnh trên. 

<img width="1899" height="746" alt="image" src="https://github.com/user-attachments/assets/8aa48b6a-0709-45c2-a8a3-43c4b2e3edac" />

<img width="961" height="494" alt="image" src="https://github.com/user-attachments/assets/bcc18e4a-fa21-4386-8608-b9a1fada13ca" />

Sau khi xong rồi ta bấm vào **Back to agent list**

<img width="1897" height="196" alt="image" src="https://github.com/user-attachments/assets/d2571224-d2f9-43bc-87cd-2f65191fc541" />

Thì ta đã được máy Windows của chúng ta. 

<img width="1909" height="963" alt="image" src="https://github.com/user-attachments/assets/8ca13099-aa4c-4f78-bf0f-1d271afdd0af" />

## Phase 4: Atomic 

Ở phase này, trên máy lab ta sẽ cài đặt Atomic Red Team để mô phỏng các kỹ thuật tấn công theo MITRE ATT&CK.

> Atomic Red Team là bộ test case mã nguồn mở, trong đó mỗi test đại diện cho một hành vi tấn công nhỏ, độc lập và dễ kiểm soát. Công cụ này giúp tạo log tấn công có chủ đích để kiểm tra khả năng ghi nhận và phát hiện của Sysmon, Windows Event Log, Wazuh/SIEM. 

Trên windows mở **powershell** với quyền admin. Xong rồi ta thực hiện các bước bên dưới.

**Bước 1**: Thêm Exclusion + Tắt Defender trước. Thì mục đích của việc này là để windows defender làm gián đoạn việc test. 

```
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
Add-MpPreference -ExclusionPath "C:\Tools"
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
```
<img width="646" height="95" alt="image" src="https://github.com/user-attachments/assets/68b0a4f0-8cee-4c69-a12b-4c7eb7acfb25" />

Tiếp theo ta vào Windows Defends bản GUI để tắt bên trong đó luôn. Ta bấm vào mũi tên xuống dưới góc màn hình rồi ấn vào cái khiên.

<img width="795" height="435" alt="image" src="https://github.com/user-attachments/assets/0ce6942e-95bd-4f7c-9b95-5cd5c9eeb746" />

Tiếp theo ta vào **Virus & threat protection**

<img width="1587" height="911" alt="image" src="https://github.com/user-attachments/assets/c788ee89-aa4b-46c5-859d-11583df04c6b" />

Tại mục **Virus & theat protection setting**. Bấm vào **Manage settings**. Rồi tắt hết tất cả trong đó. 

<img width="697" height="905" alt="image" src="https://github.com/user-attachments/assets/54668c0e-8226-4e63-8913-d8cdcfe1a35e" />

<img width="868" height="783" alt="image" src="https://github.com/user-attachments/assets/96ac2e99-3e3c-4422-b78e-3bd67574a2e6" />

**Bước 2**: Bypass để chạy script
```
Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
```

**Bước 3**: Cài Atomic Red Team
```
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

<img width="966" height="190" alt="image" src="https://github.com/user-attachments/assets/a92cf2ef-85ee-48fb-a8fb-4090d0fd15cf" />

Ta nhấn **Enter** để tiếp tục.

**XONG PHẦN SETUP**
