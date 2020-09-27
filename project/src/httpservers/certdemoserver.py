from flask import Flask

app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello World!"


def start_demo_server(cert_path, key_path):
    app.run(host="0.0.0.0",ssl_context=(cert_path, key_path), port=5001)
