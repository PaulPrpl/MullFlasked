from flask import Flask, redirect, url_for, request, json
from markupsafe import escape
from mullvad_mod import *

app = Flask(__name__)

@app.route("/", methods=['GET'])
def data():
    content = mullvad_content
    return content


@app.route("/get", methods=['GET'])
def show():

    state = request.args.get('country')
    place = request.args.get('city')
    vpn = request.args.get('server')

    rendered = updater(True, state, place, vpn)
    if not rendered:
        rendered = json.dumps({'status': '404 NOT FOUND'})

    return rendered


@app.route("/set", methods=['POST'])
def mod():

    state = request.args.get('country')
    place = request.args.get('city')
    vpn = request.args.get('server')

    rendered = updater(False, state, place, vpn)
    if not rendered:
        rendered = json.dumps({'status': '404 NOT FOUND'})

    return rendered