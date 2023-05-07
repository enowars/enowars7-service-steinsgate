from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route('/user/<username>')
def profile(username):
    return f'{username}\'s profile<br/>FLAG0101010101010110010101'

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)
