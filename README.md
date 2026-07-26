# Endpoint Monitoring (Sysmon + Wazuh)
> Made by K0g4 with love

## Mục lục
- [Giới thiệu](#giới-thiệu)
- [Cài đặt](#cài-đặt)
- [Use Cases](#use-cases)
  
## Giới thiệu

**Endpoint Monitoring** là dự án xây dựng hệ thống phát hiện mối đe dọa (Threat Detection) trên các endpoint sử dụng **Sysmon** và **Wazuh**.

Mục tiêu chính là phát hiện những hành vi bất thường trên các endpoint trong môi trường Windows.

Tập trung vào:
- **Thu thập log Sysmon** từ Windows client và đẩy về Wazuh Manager
- **Xây dựng custom rules** để phát hiện hành vi độc hại
- **Mô phỏng tấn công** (Attack Simulation) trên các endpoint
- **Validate cảnh báo** để đảm bảo độ chính xác của detection

## Cài đặt

Xem hướng dẫn cài đặt chi tiết tại [`setup.md`](./setup.md).

## Use Cases

| # | Use Case | Mô tả | File |
|---|----------|-------|------|
| 1 | Credential Access | Phát hiện hành vi đánh cắp thông tin xác thực | [`usecase/credential-access.md`](./usecase/credential-access.md) |
| 2 | Persistence | Phát hiện các kỹ thuật duy trì truy cập trái phép | [`usecase/persistence.md`](./usecase/persistence.md) |
