from flask import Flask
import os
import signal

app = Flask(__name__)


@app.route("/shutdown")
def shutdown():
    os.kill(os.getpid(), signal.SIGTERM)


def start_shutdown_server():
    app.run(host="0.0.0.0", port=5003)
