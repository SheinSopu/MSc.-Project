import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
#import asyncio
#import multipart
#from flask import Flask, redirect, url_for, request
import requests, urllib.request
import json
import os

#### Set your Slack or Teams or Mattermost webhook here
webhook_url = "https://hooks.slack.com/services/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"

#### Set the name of this honeypot instance here

honeypot_name = "My log4j honeypot"

#### Set the port you want this honeypot to listen on. Recommended port 8080 or 80

honeypot_port = 8080

if "HONEYPOT_NAME" in os.environ and os.environ["HONEYPOT_NAME"].strip() != "":
    honeypot_name = os.environ["HONEYPOT_NAME"]

if "WEBHOOK_URL" in os.environ and os.environ["WEBHOOK_URL"].strip() != "":
    webhook_url = os.environ["WEBHOOK_URL"].strip()

if "HONEYPOT_PORT" in os.environ and os.environ["HONEYPOT_PORT"].strip() != "":
    try:
        honeypot_port = int(os.environ["HONEYPOT_PORT"].strip())
    except:
        print("Invalid port: " + os.environ["HONEYPOT_PORT"])
        print("Reverting to port 8080 default")
        honeypot_port = 8080

   
app = FastAPI()

async def reportHit(request, HTTPheader):
    url_part1 = "http://ip-api.com/json/"
    ip = str(request.client.host)
    msglines = []
    msglines.append("Alert from " + honeypot_name)
    msglines.append("Suspicious request received from IP: "+ ip)
    msglines.append("The location of the IP used by the attacker: "+ str(requests.get(url_part1 + ip).json()))
    msglines.append("The HTTP method which is used by attacker is: " + HTTPheader)
    msglines.append("Review HTTP headers for payloads:")
    msglines.append("```")
    msglines.append(str(request.headers))
    msglines.append(str(await request.form()))
    msglines.append("```")

    msg = {'text':'\n '.join(msglines)}
    response = requests.post(
        webhook_url, data=json.dumps(msg),
        headers={'Content-Type':'application/json'},
        proxies=urllib.request.getproxies(),
    )
    if response.status_code != 200:
        print('Request to webhook returned an error %s, the response is:\n%s' % (response.status_code, response.text))



@app.get('/websso/SAML2/SSO/<path:hostname>')
@app.get("/", response_class=HTMLResponse)
async def home_get(request: Request):
    HTTPheader = "GET"
    if "${" in str(request.headers):
        await reportHit(request, HTTPheader)    
    return(login_form)

@app.put("/", response_class=HTMLResponse)
async def home_put(request: Request):
    HTTPheader = "PUT"
    if "${" in str(request.headers):
        await reportHit(request, HTTPheader)    
    return(login_form)

@app.delete("/", response_class=HTMLResponse)
async def home_del(request: Request):
    HTTPheader = "DELETE"
    if "${" in str(request.headers):
        await reportHit(request, HTTPheader)    
    return(login_form)

@app.head("/", response_class=HTMLResponse)
async def home_head(request: Request):
    HTTPheader = "HEAD"
    if "${" in str(request.headers):
        await reportHit(request, HTTPheader)    
    return(login_form)

@app.post("/", response_class=HTMLResponse)
async def home_post(request: Request):
    HTTPheader = "POST"
    if "${" in str(request.headers):
        reportHit(request, HTTPheader)
    
    form_data = await request.form()
    #print(form_data)
    if "${" in str(form_data):
        await reportHit(request, HTTPheader)
    return("<html><head><title>Login Failed</title></head><body><h1>Login Failed</h1><br/><a href='/'>Try again</a></body></html>")


if __name__ == '__main__':
    if not webhook_url:
        print("ERROR: WEBHOOK_URL environment variable not set! I will not be able to report exploit attempts!")
        print("For Docker, use -e WEBHOOK_URL=xxxxx or for shell use export WEBHOOK_URL=xxxxx")
    else:
        uvicorn.run("Log4j_Honeypot:app",debug=False, host='0.0.0.0', port=honeypot_port)


login_form = """<html>
<head><title>Secure Area Login</title></head>
<body>
<h1>Log in to Secure TUS Network</h1>
<style>
/* Bordered form */
form {
  border: 3px solid #f1f1f1;
}

/* Full-width inputs */
input[type=text], input[type=password] {
  width: 100%;
  padding: 12px 20px;
  margin: 8px 0;
  display: inline-block;
  border: 1px solid #ccc;
  box-sizing: border-box;
}

/* Set a style for all buttons */
button {
  background-color: #04AA6D;
  color: white;
  padding: 14px 20px;
  margin: 8px 0;
  border: none;
  cursor: pointer;
  width: 10%;
}

/* Add a hover effect for buttons */
button:hover {
  opacity: 0.8;
}

/* Extra style for the cancel button (red) */
.cancelbtn {
  width: auto;
  padding: 10px 18px;
  background-color: #f44336;
}

/* Center the avatar image inside this container */
.imgcontainer {
  text-align: center;
  margin: 24px 0 12px 0;
}

/* Avatar image */
img.avatar {
  width: 40%;
  height : 40%;
}

/* Add padding to containers */
.container {
  padding: 16px;
}

/* The "Forgot password" text */
span.psw {
  float: right;
  padding-top: 16px;
}

/* Change styles for span and cancel button on extra small screens */
@media screen and (max-width: 300px) {
  span.psw {
    display: block;
    float: none;
  }
  .cancelbtn {
    width: 100%;
  }
}
</style>
<form form method='post' action='/'>
  <div class="imgcontainer">
    <img src="https://munstergaapps.ie/wp-content/uploads/2022/01/TUS-Logo.png" alt="Avatar" class="avatar">
  </div>

  <div class="container">
    <label for="uname"><b>Username</b></label>
    <input type="text" placeholder="Enter Username" name="uname" required>

    <label for="psw"><b>Password</b></label>
    <input type="password" placeholder="Enter Password" name="psw" required>
 
    <button type="submit">Login</button>
    <label>
      <input type="checkbox" checked="checked" name="remember"> Remember me
    </label>
  </div>

  <div class="container" style="background-color:#f1f1f1">
    <button type="button" class="cancelbtn">Cancel</button>
    <span class="psw">Forgot <a href="#">password?</a></span>
  </div>
</form>
</body></html>"""
