# Minimal API Server + Web Tạo Key (xóa Android thừa)

## Files cần cho GitHub/VPS:
```
admin.html (web tạo key)
server.py (API server)
serverkey.db (auto tạo)
run_server.bat
admin_api_endpoints.md (docs)
.github/workflows/deploy.yml (optional VPS auto)
```

## Xóa thừa:
```
rm -rf AndroidKeyClient/  # Android app
rm client_android.cpp     # C++ client
# Giữ client.py/mobile_client.html nếu cần
```

## Deploy GitHub Pages (web chỉ):
1. Copy admin.html → index.html
2. git add index.html admin_api_endpoints.md
3. gh repo create --push
4. Pages live (frontend)

## Deploy VPS Backend:
```
./deploy_vps.sh  # Update để chỉ server.py + admin.html
```

**Test local:**
```
run_server.bat
http://localhost:5000  # Web + API tạo key
```

API: /login → /generate_key → /keys (admin/admin123). Android xóa OK!
