# API Check Key ĐÚNG/SAI cho Client (kết nối server của bạn)

## 1. Login Admin (để lấy token xem keys)
```
POST http://YOUR_SERVER:5000/login
Body: {"username": "admin", "password": "admin123"}
→ {"token": "eyJ..."}
```

## 2. Xem tất cả keys (check đúng/sai)
```
GET http://YOUR_SERVER:5000/keys
Header: Authorization: Bearer {token}
→ {"keys": [{"key":"1234", "status":"active", "used":0, "hwid":"..."}, ...]}
```

## 3. Client check key (ĐÚNG/SAI từ app của bạn)
**Cách 1: POST**
```
POST http://YOUR_SERVER:5000/check_key
Body: {"key": "1234", "hwid": "YOUR_MACHINE_ID"}
Response:
- {"status": "success", "remaining_hours": 720.5} → ĐÚNG
- {"status": "invalid"} → SAI key
- {"status": "expired"} → HẾT HẠN
- {"status": "invalid_device"} → Sai HWID
- {"status": "activated"} → Kích hoạt lần đầu OK
```

**Cách 2: GET đơn giản (app external)**
```
GET http://YOUR_SERVER:5000/verify?key=1234&hwid=YOUR_MACHINE_ID
Response tương tự
```

## Ví dụ Python client (từ test_api.py):
```python
import requests
resp = requests.post('http://127.0.0.1:5000/check_key', json={'key':'1234', 'hwid':'abc123'})
print(resp.json())  # {"status": "success", ...}
```

**HWID:** Machine ID duy nhất của client (e.g. CPU ID, MAC).

Server: `run_server.bat` → ready! Test: `python test_api.py`.
