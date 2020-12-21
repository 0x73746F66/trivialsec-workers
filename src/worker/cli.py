import argparse
import sys
import os
import time
from subprocess import Popen
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.config import config


def get_options() -> dict:
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--service', help='service instance', dest='service', required=True)
    parser.add_argument('-w', '--worker-id', help='unique service instance id', dest='worker_id', required=True)
    parser.add_argument('-a', '--account-id', help='Customer specific workers', dest='account_id', default=None)
    parser.add_argument('-c', '--conf', help='absolution path to the custom config file', dest='custom_config', default=None)
    parser.add_argument('-p', '--pid-file', help='absolution path to the application pid file', dest='pid_file', default='/srv/app/worker.pid')

    args = parser.parse_args()
    try:
        with open(args.pid_file, 'w') as pid_fd:
            pid_fd.write(str(os.getpid()))
    except Exception as ex:
        print(ex)
        sys.exit(1)

    if args.custom_config is not None:
        config.custom_config = args.custom_config
        config.configure()
    opts = {**args.__dict__, **config.__dict__}
    if opts.get('worker_id') is None:
        opts['worker_id'] = opts.get('node_id')

    return opts

def s3_upload(source_path: str, destination_path: str) -> str:
    retcode = None
    json_response = ''
    params = [
        'python3.8',
        '-u',
        '-d',
        '/srv/app/s3_upload.py',
        '--source-path',
        source_path,
        '--destination-path',
        destination_path,
    ]
    logger.info(' '.join(params))
    try:
        proc = Popen(params)
        retcode = proc.poll()
        while retcode is None:
            time.sleep(1)
            retcode = proc.poll()

    finally:
        if proc:
            json_response = f"{proc.stdout or ''}".strip()
            error = f"{proc.stderr or ''}".strip()
            proc.terminate()

    if retcode != 0:
        raise ValueError(f's3_upload exited with {retcode} {error}')

    logger.info(json_response)
    return json_response
