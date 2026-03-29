# Phần 2: CLIENT TOOL CHECK KEY TỰ ĐỘNG
import requests
import uuid
import time

def get_hwid():
    return str(uuid.getnode())

key = input("Nhập key: ")

while True:
    r = requests.post("http://103.249.201.186:5000/check_key", json={
        "key": key,
        "hwid": get_hwid()
    })

    data = r.json()

    if data["status"] == "expired":
        print("Key hết hạn")
        break

    elif data["status"] == "invalid":
        print("Key sai")
        break

    else:
        print("Key hợp lệ")

    time.sleep(10)
