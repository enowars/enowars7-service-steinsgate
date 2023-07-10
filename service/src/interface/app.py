from flask import Flask, render_template, request
import subprocess
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
      print("COMMAND:", " ".join(args))
      resp = subprocess.check_output(args)
      return render_template('index.html', response=resp)
   return render_template('index.html')

if __name__ == '__main__':
   app.run(host="0.0.0.0", port=4420)