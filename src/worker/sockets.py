import json
import socketio
from retry.api import retry
from gunicorn.glogging import logging
from worker.cli import get_options


logger = logging.getLogger(__name__)

sio = socketio.Client()

@sio.event
def connect():
    logger.info("connected")

@sio.event
def connect_error():
    logger.info("connection failed")

@sio.event
def disconnect():
    logger.info("disconnected")

@retry((Exception), tries=5, delay=1, backoff=2)
def close_socket():
    sio.disconnect()

@retry((ConnectionError), tries=5)
def send_event(event: str, data: dict):
    options = get_options()
    if not sio.connected:
        try:
            host = f"{options['backend'].get('socket_scheme')}{options['backend'].get('socket_domain')}"
            logger.info(f'socketio.Client CONNECT {host}')
            sio.connect(host)

        except Exception as err:
            raise ConnectionError from err
    json_data = json.dumps(data, sort_keys=True, default=str)
    logger.debug(f"Sending event {event} {json_data}")
    try:
        sio.emit(event, json_data)
    except Exception as err:
        raise ConnectionError from err
