<<<<<<< HEAD
# Key Manager Server

## Quick Start
1. Install dependencies: `pip install -r requirements.txt`
2. Local: `run_server.bat` (Windows) → http://localhost:5000/admin (admin/admin123)
3. VPS Deploy: `./deploy_vps.sh` → http://103.249.201.186:5000/admin

## Mobile/Client Access
- **Localhost**: Only same machine ❌
- **VPS IP**: http://103.249.201.186:5000/check_key or http://103.249.201.186:5000/verify?key=XXXX&hwid=YYY ✅ Phones work!
- **Domain** (optional): https://yourdomain.com/check_key

## API
`admin_api_endpoints.md` & `client_check_key_guide.md`

## GitHub Pages
`index.html` live demo (frontend only)

**Test:** python test_api.py

