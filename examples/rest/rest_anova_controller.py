import datetime
import logging
from threading import Timer

from flask import Request

from examples.rest.rest import on_json_loading_failed
from pycirculate.anova import AnovaController


class RESTAnovaController(AnovaController):
    """
    This version of the Anova Controller will keep a connection open over bluetooth
    until the timeout has been reach.

    NOTE: Only a single BlueTooth connection can be open to the Anova at a time.
    """

    TIMEOUT = 5 * 60 # Keep the connection open for this many seconds.
    TIMEOUT_HEARTBEAT = 20
    LOOPBACK = False

### TODO NEXT: can't run this on macos becaus bluepy is linux only. would need some kind of
    # TODO seam to allow this to run on macos, or just develop on linux

    def __init__(self, mac_address, connect=True, logger=None):
        self.last_command_at = datetime.datetime.now()
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger()
        # self.anova_controller = AnovaController(mac_address, connect=connect)
        super(RESTAnovaController, self).__init__(mac_address, connect=connect)
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

    def context(self):
        if not self.is_connected():
            return {
                "message": "Anova is not connected"
            }

        timer = self.read_timer()
        self.logger.info("timer in context:" + timer)
        timer = timer.split()
        output = {
            "anova_status": self.anova_status(),
            "timer_status": {"minutes_remaining": int(timer[0]), "status": timer[1], },
            "target_temp": self.read_set_temp(),
            "current_temp": float(self.read_temp()),
            "last_updated": datetime.datetime.now()
        }
        return output