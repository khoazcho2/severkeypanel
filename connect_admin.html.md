# Hướng dẫn kết nối API với admin.html

## 1. Chạy Backend Server (bắt buộc)
```
run_server.bat
```
hoặc  
```
python server.py
```
→ Server chạy http://localhost:5000 (hoặc VPS IP:5000)

## 2. Mở Admin Panel
```
start http://localhost:5000
```
→ Auto serve admin.html + login admin/admin123

## 3. Kết nối Custom Frontend (như admin.html deploy GitHub)
Trong JS của HTML, set `API_BASE`:
```js
const API_BASE = 'http://YOUR_SERVER_IP:5000';  // e.g. http://localhost:5000 hoặc https://vps.example.com
```
admin.html hiện dùng `window.location.origin` (auto localhost/VPS).

## APIs chính (chi tiết trong admin_api_endpoints.md)
- Login → token  
- GET /keys (Bearer token)  
- POST /generate_key  
- POST /check_key (client)

## Deploy GitHub Pages + Backend VPS
1. Frontend: GitHub Pages host admin.html/index.html (static)  
2. Backend: `./deploy_vps.sh` lên VPS → API live  
3. Update JS: `const API_BASE = 'https://vps-domain.com';`

Test ngay: run_server.bat → localhost:5000 ✅
