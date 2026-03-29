import requests
import json

# Test login
resp = requests.post('http://127.0.0.1:5000/login', json={'username': 'admin', 'password': 'admin123'})
print('Login:', resp.status_code, resp.json())

token = resp.json().get('token')
headers = {'Authorization': f'Bearer {token}'}

# Generate 30-day 4-digit key (e.g., 1234)
resp = requests.post('http://127.0.0.1:5000/generate_key', json={'duration_days': 30, 'max_devices': 1}, headers=headers)
print('Generate Key:', resp.status_code, resp.json())

# Get all keys
resp = requests.get('http://127.0.0.1:5000/keys', headers=headers)
keys = resp.json().get('keys', [])
print('Keys:', len(keys))
for k in keys[:3]:
    print(f"  Key: {k['key']}, Days: {k['duration_days']}, Expire: {k['expire_at']}")
