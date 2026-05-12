import requests

url = "http://localhost:8080/login"
cookies = {"SUSLURE_TOKEN": "eyJhbGciOiJub25lIn0.fake.payload"}
data = {"username": "admin", "password": "password"}

r = requests.post(url, cookies=cookies, data=data, allow_redirects=True)
print("Landed on:", r.url)
print("Status:", r.status_code)
