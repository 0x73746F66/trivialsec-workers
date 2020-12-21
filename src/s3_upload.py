import argparse
import json
import sys
import boto3
from trivialsec.helpers.config import config


def main(options: dict):
    response = ''
    aws_session = boto3.Session(region_name=options['aws'].get('region_name'))
    s3_client = aws_session.client('s3')
    with open(options.get('source_path'), 'r') as buff:
        response = s3_client.put_object(
            Bucket=options['aws'].get('archive_bucket'),
            ACL='bucket-owner-full-control',
            Body=buff.read(),
            Key=options.get('dest_path').strip(),
            StorageClass='STANDARD_IA',
        )
    print(json.dumps(response, default=str))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--conf', help='absolution path to the custom config file', dest='custom_config')
    parser.add_argument('-s', '--source-path', help='file path source', dest='source_path', required=True)
    parser.add_argument('-d', '--destination-path', help='file path destination', dest='dest_path', required=True)

    args = parser.parse_args()
    if args.custom_config is not None:
        config.config_file = args.custom_config
        config.configure()
    main({**args.__dict__, **config.__dict__})
    sys.exit(0)
