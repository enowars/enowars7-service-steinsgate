from flask import Flask, render_template, request
import subprocess
import json
import base64

app = Flask(__name__)

@app.route('/', methods = ['POST', 'GET'])
def home():
   if request.method == 'POST':
      url = request.form['url']
      args = []
      method = request.form['method']
      header1 = request.form['header1']
      header2 = request.form['header2']
      payload = request.form['payload']
      if method and method != "":
        args.append("-x")
        args.append(method) 
      if header1 and header1 != "":
        args.append("-H")
        args.append(header1)
      if header2 and header2 != "":
        args.append("-H")
        args.append(header2)
      if payload and payload != "":
        args.append("-d")
        args.append(payload)
      args = ["python3", "client.py", "-k", url] + args
      print("Command: ", " ".join(args))
      resp = subprocess.check_output(args)
      print("Response: ", resp)
      if resp != b"" and resp != b"WORKING\n":
        resp_cooked = json.dumps(json.loads(resp.decode()), indent=2)
      else:
        resp_cooked = resp.decode()
      return render_template('index.html', method=method, url=url, header1=header1, header2=header2, payload=payload, response=resp_cooked, responseB64=base64.b64encode(resp).decode())
   return render_template('index.html', method="GET", url="https://proxy:4433/", header1="", header2="", payload="", response="", responseB64=base64.b64encode(b"").decode())

if __name__ == '__main__':
   app.run(host="0.0.0.0", port=4420)
