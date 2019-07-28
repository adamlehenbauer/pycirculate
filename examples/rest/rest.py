"""
Example of using pycirculate with a simple Flask RESTful API.

Make sure to send requests with the HTTP header "Content-Type: application/json".

NOTE: Only a single BlueTooth connection can be open to the Anova at a time.  So
if you want to scale this API with multi-processing, keep that in mind to prevent errors
such as:
    `BTLEException: Failed to connect to peripheral 78:A5:04:38:B3:FA, addr type: public`
"""
from flask import Flask, request, jsonify, abort, make_response, render_template, _request_ctx_stack, redirect, url_for, flash

import logging
import json
import os
import sys
import warnings
import pdb

app = Flask(__name__)

ANOVA_MAC_ADDRESS = "F4:B8:5E:B3:37:EC"


def on_json_loading_failed(self):
    ctx = _request_ctx_stack.top
    pdb.set_trace()


# Error handlers

@app.errorhandler(400)
def bad_request(error):
    app.logger.error("bad_request handler with exception: %s", error)
    return make_response(jsonify({'error': 'Bad request.'}), 400)


@app.errorhandler(404)
def timeout_atnot_found(error):
    return make_response(jsonify({'error': 'Not found.'}), 404)


@app.errorhandler(500)
def server_error(error):
    return make_response(jsonify({'error': 'Server error.'}), 500)


def make_error(status_code, message, sub_code=None, action=None, **kwargs):
    """
    Error with custom message.
    """
    data = {
        'status': status_code,
        'message': message,
    }
    if action:
        data['action'] = action
    if sub_code:
        data['sub_code'] = sub_code
    data.update(kwargs)
    response = jsonify(data)
    response.status_code = status_code
    return response

# REST endpoints


@app.route('/', methods=["GET"])
def index():
    return render_template('app.html', anova_context=app.anova_controller.context())


@app.route("/connect", methods=["GET"])
def try_connect():
    app.anova_controller, error = resolve_controller(ANOVA_MAC_ADDRESS, app.logger)
    #if error:
    #    flash("Error trying bluetooth connection" + error)
    # return redirect(url_for("webapp"))
    if error:
        return error
    else:
        return "Connect apparently successful"


@app.route("/refresh", methods=["GET"])
def refresh():
    try:
        timer = app.anova_controller.read_timer()
        timer = timer.split()
        output = app.anova_controller.anova_context()
    except Exception as exc:
        app.logger.error(exc)
        return make_error(500, "{0}: {1}".format(repr(exc), str(exc)))

    return jsonify({"anova": output, "message": "Refreshed"})


@app.route('/noop', methods=["GET"])
def noop():
    return jsonify({"operation": "noop"})


@app.route('/debug', methods=["GET"])
def debug():
    return jsonify


@app.route('/app', methods=["GET"])
def webapp():
    return render_template('app.html', anova_context=app.anova_controller.context())


@app.route('/temp', methods=["GET"])
def get_temp():
    try:
        output = {
            "current_temp": float(app.anova_controller.read_temp()),
            "set_temp": float(app.anova_controller.read_set_temp()),
            "unit": app.anova_controller.read_unit(),
        }
    except Exception as exc:
        app.logger.error(exc)
        return make_error(500, "{0}: {1}".format(repr(exc), str(exc)))

    return jsonify(output)


@app.route('/temp', methods=["POST"])
def set_temp():
    try:
        temp = request.get_json()['temp']
    except (KeyError, TypeError) as exc:
        app.logger.error("Adam error")
        app.logger.error(exc)
        abort(400)
    except Exception as e:
        app.logger.error("unexpected exception: %s", e)
        abort(400)
    except:
        e = sys.exec_info()[0]
        app.logger.error("any exception: %s", e)
    temp = float(temp)
    setTempResult = app.anova_controller.set_temp(temp)
    output = {
        "message": "Target temp updated to " + str(setTempResult),
        "anova": app.anova_controller.context()
    }

    return jsonify(output)


@app.route('/stop', methods=["POST"])
def stop_anova():
    # disabled for safety
    stop = app.anova_controller.stop_anova()
    #stop = "s"
    #if stop == "s":
        #message = "Stopping"
    output = {"message": stop,
            "anova": app.anova_controller.anova_context()}

    return jsonify(output)


@app.route('/start', methods=["POST"])
def start_anova():
    # commented out for safety
    status = app.anova_controller.start_anova()
    #status = "starting"
    if status == "s" or status == "start":
        message = "Starting"
    else:
        message = "Unexpected result: " + status
    output = {"message": message,
            "anova": app.anova_controller.anova_context()}

    return jsonify(output)


@app.route('/set-timer', methods=["POST"])
def set_timer():
    try:
        minutes = request.get_json()['minutes']
    except (KeyError, TypeError):
        abort(400)
    output = {
        "set_minutes": int(app.anova_controller.set_timer(minutes))
    }
    return jsonify(output)


@app.route('/start-timer', methods=["POST"])
def start_timer():
    # Anova must be running to start the timer.
    app.anova_controller.start_anova()
    output = {
        "timer_status": app.anova_controller.start_timer()
    }
    return jsonify(output)


@app.route('/stop-timer', methods=["POST"])
def stop_timer():
    output = {"timer_status": app.anova_controller.stop_timer()}
    return jsonify(output)


@app.route('/set-timeout', methods=["POST"])
def set_timeout():
    """
    Adjust the Bluetooth connection timeout length.
    """
    try:
        seconds = int(request.get_json()['timeout_seconds'])
    except (KeyError, TypeError):
        abort(400)
    app.anova_controller.set_timeout(seconds)
    output = {"timeout_seconds": seconds,}
    return jsonify(output)


class AuthMiddleware(object):
    """
    HTTP Basic Auth wsgi middleware.  Must be used in conjunction with SSL.
    """

    def __init__(self, app, username, password):
        self._app = app
        self._username = username
        self._password = password

    def __call__(self, environ, start_response):
        if self._authenticated(environ.get('HTTP_AUTHORIZATION')):
            return self._app(environ, start_response)
        return self._login(environ, start_response)

    def _authenticated(self, header):
        from base64 import b64decode
        if not header:
            return False
        _, encoded = header.split(None, 1)
        decoded = b64decode(encoded).decode('UTF-8')
        username, password = decoded.split(':', 1)
        return (self._username == username) and (self._password == password)

    def _login(self, environ, start_response):
        start_response('401 Authentication Required',
            [('Content-Type', 'application/json'),
             ('WWW-Authenticate', 'Basic realm="Login"')])
        output = {"error": "Login"}
        return [json.dumps(output)]


class OfflineAnovaController(object):
    def is_connected(self):
        return False

    def context(self):
        return {
            "online": "false",
            "anova_status": "Offline",
            "timer_status": {}
        }


def resolve_controller(mac, logger):
    try:
        from examples.rest.rest_anova_controller import RESTAnovaController
        return RESTAnovaController(mac, logger=logger), None
    except:
        print("Unexpected error:", sys.exc_info()[1])
        return OfflineAnovaController(), sys.exc_info()[1].message


def main():
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)

    app.anova_controller, _ = resolve_controller(ANOVA_MAC_ADDRESS, app.logger)

    try:
        username = os.environ["PYCIRCULATE_USERNAME"]
        password = os.environ["PYCIRCULATE_PASSWORD"]
        app.wsgi_app = AuthMiddleware(app.wsgi_app, username, password)
    except KeyError:
        warnings.warn("Enable HTTP Basic Authentication by setting the 'PYCIRCULATE_USERNAME' and 'PYCIRCULATE_PASSWORD' environment variables.")

    # adhoc context - doesn't work with my version of openssl, algorithm is too weak
    #app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
    try:
        cert = os.environ["PYCIRCULATE_CERT"]
        key = os.environ["PYCIRCULATE_KEY"]
    except:
        pass

    #app.logger.info("Using cert [%s] and key [%s]", cert, key)
    #app.run(host='0.0.0.0', port=5000, ssl_context=(cert, key))
    app.logger.info("Starting up for Adam")
    app.run(host='0.0.0.0', port=5000, ssl_context=None, debug=False, use_reloader=False)

if __name__ == '__main__':
    main()
