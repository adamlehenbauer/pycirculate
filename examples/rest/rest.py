"""
Example of using pycirculate with a simple Flask RESTful API.

Make sure to send requests with the HTTP header "Content-Type: application/json".

NOTE: Only a single BlueTooth connection can be open to the Anova at a time.  So
if you want to scale this API with multi-processing, keep that in mind to prevent errors
such as:
    `BTLEException: Failed to connect to peripheral 78:A5:04:38:B3:FA, addr type: public`
"""
from flask import Flask, request, jsonify, abort, make_response, render_template, Request, _request_ctx_stack
from pycirculate.anova import AnovaController
from threading import Timer
import datetime
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

class RESTAnovaController(AnovaController):
    """
    This version of the Anova Controller will keep a connection open over bluetooth
    until the timeout has been reach.

    NOTE: Only a single BlueTooth connection can be open to the Anova at a time.
    """

    TIMEOUT = 5 * 60 # Keep the connection open for this many seconds.
    TIMEOUT_HEARTBEAT = 20
    LOOPBACK = True

    def __init__(self, mac_address, connect=True, logger=None):
        self.last_command_at = datetime.datetime.now()
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger()
        super(RESTAnovaController, self).__init__(mac_address, connect=connect)
        #print "connect=", connect
        #print "super(RESTAnovaController, self): ", super(RESTAnovaController, self)
        #print "super(RESTAnovaController, self): ", super(AnovaController, self)
        #super(AnovaController, self).__init__(mac_address, connect=connect)
        Request.on_json_loading_failed = on_json_loading_failed

    def set_timeout(self, timeout):
        """
        Adjust the timeout period (in seconds).
        """
        self.TIMEOUT = timeout

    def timeout(self, seconds=None):
        """
        Determines whether the Bluetooth connection should be timed out
        based on the timestamp of the last exectuted command.
        """
        if not seconds:
            seconds = self.TIMEOUT
        timeout_at = self.last_command_at + datetime.timedelta(seconds=seconds)
        if datetime.datetime.now() > timeout_at:
            self.close()
            self.logger.info('Timeout bluetooth connection. Last command ran at {0}'.format(self.last_command_at))
        else:
            self._timeout_timer = Timer(self.TIMEOUT_HEARTBEAT, lambda: self.timeout())
            self._timeout_timer.setDaemon(True)
            self._timeout_timer.start()
            self.logger.debug('Start connection timeout monitor. Will idle timeout in {0} seconds.'.format(
                (timeout_at - datetime.datetime.now()).total_seconds())) 

    def connect(self):
        if not self.LOOPBACK:
            super(RESTAnovaController, self).connect()
            self.last_command_at = datetime.datetime.now()
            self.timeout()

    def close(self):
        if not self.LOOPBACK:
            super(RESTAnovaController, self).close()
            try:
                self._timeout_timer.cancel()
            except AttributeError:
                pass

    def _send_command(self, command):
        if not self.LOOPBACK:
            if not self.is_connected:
                self.connect()
            self.last_command_at = datetime.datetime.now()
            return super(RESTAnovaController, self)._send_command(command)


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
    try:
        timer = app.anova_controller.read_timer()
        timer = timer.split()
        output = {
                "anova_status": app.anova_controller.anova_status(),
                "timer_status": {"minutes_remaining": int(timer[0]), "status": timer[1],},
                "target temp": app.anova_controller.read_set_temp(),
                "current temp": app.anova_controller.read_temp()
                }
    except Exception as exc:
        app.logger.error(exc)
        return make_error(500, "{0}: {1}".format(repr(exc), str(exc)))

    return jsonify(output)

@app.route('/noop', methods=["GET"])
def noop():
    return jsonify({"operation": "noop"})

def anova_context():
    timer = app.anova_controller.read_timer()
    timer = timer.split()
    #pdb.set_trace()
    output = {
                "anova_status": app.anova_controller.anova_status(),
                "timer_status": {"minutes_remaining": int(timer[0]), "status": timer[1],},
                "target_temp": str(app.anova_controller.read_set_temp()),
                "current_temp": float(app.anova_controller.read_temp())
                }
    return output

@app.route('/app', methods=["GET"])
def webapp():
    return render_template('app.html', anova_context=anova_context())

@app.route('/temp', methods=["GET"])
def get_temp():
    try:
        output = {"current_temp": float(app.anova_controller.read_temp()), "set_temp": float(app.anova_controller.read_set_temp()), "unit": app.anova_controller.read_unit(),}
    except Exception as exc:
        app.logger.error(exc)
        return make_error(500, "{0}: {1}".format(repr(exc), str(exc)))

    return jsonify(output)

@app.route('/temp', methods=["POST"])
def set_temp():
#    pdb.set_trace()
    app.logger.info("request: %s", request)
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
    output = {
            "message": "Target temp updated to " + str(temp),
            "set_temp": float(app.anova_controller.set_temp(temp))}

    return jsonify(output)

@app.route('/stop', methods=["POST"])
def stop_anova():
    stop = app.anova_controller.stop_anova()
    if stop == "s":
        stop = "stopped"
    output = {"status": stop,}

    return jsonify(output)

@app.route('/start', methods=["POST"])
def start_anova():
    status = app.anova_controller.start_anova()
    if status == "s":
        status = "starting"
    output = {"status": status,}

    return jsonify(output)

@app.route('/set-timer', methods=["POST"])
def set_timer():
    try:
        minutes = request.get_json()['minutes']
    except (KeyError, TypeError):
        abort(400)
    output = {"set_minutes": int(app.anova_controller.set_timer(minutes)),}
    return jsonify(output)

@app.route('/start-timer', methods=["POST"])
def start_timer():
    # Anova must be running to start the timer.
    app.anova_controller.start_anova()
    output = {"timer_status": app.anova_controller.start_timer()}
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


def main():
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)

    app.anova_controller = RESTAnovaController(ANOVA_MAC_ADDRESS, logger=app.logger)

    try:
        username = os.environ["PYCIRCULATE_USERNAME"]
        password = os.environ["PYCIRCULATE_PASSWORD"]
        app.wsgi_app = AuthMiddleware(app.wsgi_app, username, password)
    except KeyError:
        warnings.warn("Enable HTTP Basic Authentication by setting the 'PYCIRCULATE_USERNAME' and 'PYCIRCULATE_PASSWORD' environment variables.")

    # adhoc context - doesn't work with my version of openssl, algorithm is too weak
    #app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
    cert = os.environ["PYCIRCULATE_CERT"]
    key = os.environ["PYCIRCULATE_KEY"]
    app.logger.info("Using cert [%s] and key [%s]", cert, key)
    app.run(host='0.0.0.0', port=5000, ssl_context=(cert, key))
    app.logger.info("Starting up for Adam")
    #app.run(host='0.0.0.0', port=5000, ssl_context=None, debug=False, use_reloader=False)

if __name__ == '__main__':
    main()
