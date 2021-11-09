import logging
import argparse
import sys
import os
import time
from subprocess import Popen
from trivialsec.helpers.config import config


logger = logging.getLogger(__name__)

def get_options() -> dict:
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--service-id', help='service instance', dest='service_type_id', default=None)
    parser.add_argument('-n', '--service-name', help='service instance', dest='service_type_name', default=None)
    parser.add_argument('-w', '--worker-id', help='unique service instance id', dest='worker_id', default=None)
    parser.add_argument('-a', '--account-id', help='Customer specific workers', dest='account_id', default=None)
    parser.add_argument('-p', '--pid-file', help='absolution path to the application pid file', dest='pid_file', default='/srv/app/worker.pid')
    parser.add_argument('-s', '--only-show-errors', help='set logging level to ERROR (default CRITICAL)', dest='log_level_error', action="store_true")
    parser.add_argument('-q', '--quiet', help='set logging level to WARNING (default CRITICAL)', dest='log_level_warning', action="store_true")
    parser.add_argument('-v', '--verbose', help='set logging level to INFO (default CRITICAL)', dest='log_level_info', action="store_true")
    parser.add_argument('-vv', '--debug', help='set logging level to DEBUG (default CRITICAL)', dest='log_level_debug', action="store_true")
    args = parser.parse_args()
    log_level = logging.CRITICAL
    if args.log_level_error:
        log_level = logging.ERROR
    if args.log_level_warning:
        log_level = logging.WARNING
    if args.log_level_info:
        log_level = logging.INFO
    if args.log_level_debug:
        log_level = logging.DEBUG

    args = parser.parse_args()
    try:
        with open(args.pid_file, 'w', encoding='utf8') as pid_fd:
            pid_fd.write(str(os.getpid()))
    except Exception as ex:
        print(ex)
        sys.exit(1)

    opts = {
        'log_level': log_level,
        'account_id': args.account_id,
        'pid_file': args.pid_file,
        'worker_id': args.worker_id,
        'service_type_id': args.service_type_id,
        'service_type_name': args.service_type_name,
    }
    if opts.get('worker_id') is None:
        opts['worker_id'] = config.node_id

    return opts

def s3_upload_external(source_path :str, destination_path :str) -> str:
    retcode = None
    json_response = ''
    params = [
        'python3',
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
