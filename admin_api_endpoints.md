# API Endpoints cho admin.html (từ server.py)

## Authentication
**POST /login**  
```
Body: {"username": "admin", "password": "admin123"}
Response: {"token": "eyJ..."}
```
Default: admin/admin123 → JWT Bearer token

## Admin Dashboard
**GET /keys** `Authorization: Bearer {token}`  
```
Response: {"keys": [{"id":1,"key":"1234","max_devices":1,"used":0,"duration_days":30,"status":"active","created_by":"admin","first_used":null,"expire_at":"2024-...","hwid":null}, ...]}
```

**POST /generate_key** `Authorization: Bearer {token}`  
```
Body: {"duration_days": 0, "max_devices": 1}
Response: {"key": "5678"}
```

## Client Verify Key
**POST /check_key**  
```
Body: {"key": "1234", "hwid": "machine-id-abc"}
Response: {"status": "success", "remaining_hours": 720.5} | {"status": "expired"} | {"status": "activated"}
```

**GET /verify?key=1234&hwid=abc** (external apps)  
```
Response tương tự
```

## Serve UI
**GET /** → admin.html

Server: `python server.py` (port 5000, SQLite serverkey.db)

**Lưu ý GitHub Pages**: Chỉ static HTML, API cần backend riêng!
