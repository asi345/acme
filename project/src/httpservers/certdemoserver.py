from flask import Flask

app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello World!"


def start_demo_server(cert_path, key_path, host="0.0.0.0"):
    app.run(host=host, ssl_context=(cert_path, key_path), port=5001)
