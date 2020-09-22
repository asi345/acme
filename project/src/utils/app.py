from flask import Flask
import os
import signal

app = Flask(__name__)


@app.route("/")
def hello_world():
    return "Hello, World!"


@app.route("/shutdown")
def shutdown():
    os.kill(os.getpid(), signal.SIGTERM)
