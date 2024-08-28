"""
Main app file, all api route are declared there
"""

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from infrastructure.data.args import Args
from infrastructure.data.env_reader import EnvReader
from infrastructure.data.token import generate_token

args_checker = Args()

app = Flask(__name__)
CORS(app)

env_reader = EnvReader()
env_reader.load()


@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({'status': 'pong'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
