"""
Ứng dụng mẫu kết nối với Server Key qua URL
Cách sử dụng: python app_client.py
"""

import requests
import uuid
import time
import os

# Cấu hình server
SERVER_URL = "http://103.249.201.186:5000"  # VPS IP

def get_hwid():
    """Lấy Hardware ID của máy"""
    return str(uuid.getnode())

def verify_key(key, hwid):
    """
    Xác thực key qua URL với method GET
    Endpoint: /verify?key=KEY&hwid=HWID
    """
    url = f"{SERVER_URL}/verify"
    params = {
        "key": key,
        "hwid": hwid
    }
    
    try:
        response = requests.get(url, params=params)
        return response.json()
    except requests.exceptions.ConnectionError:
        return {"status": "error", "message": "Không thể kết nối đến server"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def main():
    print("=" * 50)
    print("  Ứng dụng kết nối Server Key")
    print("=" * 50)
    print(f"Server: {SERVER_URL}")
    print(f"HWID của máy: {get_hwid()}")
    print("=" * 50)
    
    # Nhập key từ người dùng
    key = input("\nNhập key của bạn: ").strip()
    
    if not key:
        print("Key không được để trống!")
        return
    
    print("\nĐang xác thực key...")
    print("-" * 50)
    
    # Xác thực key
    result = verify_key(key, get_hwid())
    
    # Hiển thị kết quả
    print(f"Trạng thái: {result.get('status')}")
    print(f"Thông báo: {result.get('message', 'Không có')}")
    
    if 'remaining_hours' in result:
        print(f"Thời hạn còn lại: {result['remaining_hours']} giờ")
    
    if 'expire_at' in result:
        print(f"Hết hạn vào: {result['expire_at']}")
    
    print("-" * 50)
    
    # Xử lý theo trạng thái
    if result.get("status") == "success":
        print("✅ Key hợp lệ! Bạn có thể sử dụng ứng dụng.")
    elif result.get("status") == "activated":
        print("✅ Key đã được kích hoạt thành công!")
    elif result.get("status") == "expired":
        print("❌ Key đã hết hạn. Vui lòng gia hạn.")
    elif result.get("status") == "invalid":
        print("❌ Key không tồn tại hoặc sai.")
    elif result.get("status") == "invalid_device":
        print("❌ Key đã được bind với máy khác.")
    else:
        print("❌ Lỗi không xác định.")

if __name__ == "__main__":
    main()
