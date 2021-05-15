"""Misc helper functions."""

import time
import logging
import socket
import functools

logger = logging.getLogger(__name__)


class TimeIt(object):
    def __init__(self, description):
        self.description = description

    def __enter__(self):
        self._start = time.time()

    def __exit__(self, type, value, traceback):
        delta = int(time.time() - self._start)
        logger.info("{}: {}min {}sec".format(
            self.description,
            delta // 60,
            delta % 60))


@functools.lru_cache(maxsize=None)
def wait_for(server, port, timeout=30):
    """Wait for the provided server to be ready at the TCP level."""
    s = socket.socket()
    end = time.monotonic() + timeout
    while True:
        next_timeout = end - time.monotonic()
        if next_timeout < 0:
            raise TimeoutError(f"{server}:{port} not ready "
                               f"after {timeout} seconds")
        s.settimeout(next_timeout)
        try:
            s.connect((server, port))
        except socket.timeout:
            logger.info(f"cannot connect to {server}:{port} "
                        f"after {next_timeout} seconds")
            continue
        except socket.error as e:
            logger.info(f"{server}:{port} not reachable: {e}")
            time.sleep(min(next_timeout, 1, timeout/10))
            continue
        s.close()
        break
