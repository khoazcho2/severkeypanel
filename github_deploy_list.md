# Tóm lại: Files thêm vào GitHub cho admin.html + full project

## 1. **Chỉ Frontend (GitHub Pages)**
```
admin.html → rename/copy thành index.html (bắt buộc cho root URL)
README.md (mô tả project)
```

## 2. **Full Stack (Recommend)**
```
├── admin.html (hoặc index.html)
├── server.py (backend API)
├── run_server.bat
├── test_api.py (test)
├── client.py (Python client ví dụ)
├── client_android.cpp (C++ client)
├── AndroidKeyClient/ (Android app folder)
├── mobile_client.html (mobile UI)
├── deploy_vps.sh (deploy backend)
├── admin_api_endpoints.md (API docs)
├── connect_admin.html.md (setup)
├── client_check_key_guide.md (client verify)
├── .gitignore (venv/, *.db, builds/)
└── README.md
```

## Lệnh deploy (sau git init/add/commit):
```
winget install GitHub.cli
gh repo create key-manager --public --push
# Browser: Settings > Pages > Deploy from main branch
```

**Pages live:** https://username.github.io/key-manager  
**Backend:** VPS qua deploy_vps.sh (Pages chỉ static).

Thêm tất cả → commit/push ngay!
