from os import path, isatty, makedirs
# from datetime import datetime
# import errno
# import time
import sys
import json
import argparse
from trivialsec import models, helpers
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.config import config
# from worker.sockets import close_socket


logger.configure(log_level=config.log_level)
logger.create_stream_logger(colourise=isatty(2))
logger.create_file_logger(file_path=config.log_file)

def main(job: models.JobRun) -> bool:
    for line in sys.stdin:
        # send to browser via sockets
        print(line)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--job-id', dest='job_id', required=True)
    args = parser.parse_args()

    current_job = models.JobRun(job_run_id=args.job_id)
    current_job.hydrate()

    try:
        main(current_job)
        logger.info(f'Finished service {current_job.node_id} worker {current_job.worker_id}')
    except Exception as ex:
        logger.exception(ex)

    # close_socket()
    # sys.exit(0)
