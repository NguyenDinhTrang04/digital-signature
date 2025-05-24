# Hướng Dẫn Cài Đặt Project

## Yêu Cầu Hệ Thống
- Python 3.8 trở lên
- pip (trình quản lý gói Python)
- Node.js (nếu cần chạy các công cụ frontend)

## Cài Đặt

### 1. Clone Repository
```bash
git clone <repository-url>
cd RSA
```

### 2. Tạo Virtual Environment (khuyến nghị)
```bash
python -m venv venv
source venv/bin/activate # Trên Linux/MacOS
venv\Scripts\activate   # Trên Windows
```

### 3. Cài Đặt Các Gói Phụ Thuộc
```bash
pip install -r requirements.txt
```

### 4. Chạy Ứng Dụng
```bash
python app.py
```

Ứng dụng sẽ chạy tại: [http://localhost:5000](http://localhost:5000)

## Các Chức Năng Chính
- Tạo cặp khóa RSA (khóa công khai và khóa riêng)
- Mã hóa và giải mã văn bản
- Ký số và xác minh chữ ký số
- Phòng chat thời gian thực với mã hóa tin nhắn
- Truyền file mã hóa

## Lưu Ý
- Đảm bảo rằng bạn không chia sẻ khóa riêng (private key) với bất kỳ ai.
- Nếu gặp lỗi, kiểm tra lại các gói phụ thuộc đã được cài đặt đúng chưa.

## Thư Mục
- `app.py`: File chính của ứng dụng.
- `templates/`: Chứa các file giao diện HTML.
- `uploads/`: Thư mục lưu trữ file được tải lên.

## Liên Hệ
Nếu có bất kỳ vấn đề nào, vui lòng liên hệ qua email: trangnguyendinh17@gmail.com
