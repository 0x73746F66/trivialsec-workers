from os import path
from urllib.parse import urlsplit
from datetime import datetime
import logging
import hmac
import hashlib
import json
import requests
from retry.api import retry
from trivialsec.models.webhook import Webhooks


logger = logging.getLogger(__name__)

@retry((ConnectionError), tries=5)
def send_webhook(account_id: int, event_name :str, data :dict, http_method :str = 'POST'):
    json_data = json.dumps(data, sort_keys=True, default=str)
    for webhook in Webhooks().find_by([('account_id', account_id), ('active', 1)]):
        target = urlsplit(webhook.target)
        target_url = f'https://{target.netloc}{path.join(target.path, event_name)}'
        logger.debug(f"Sending webhook {target_url}")
        now = datetime.utcnow()
        try:
            request = requests.Request(http_method, target_url, json=json_data, headers={
                'Content-Type': 'application/json',
                'X-Digest': 'HMAC-SHA3-512',
                'X-Date': now.isoformat()
            })
            prepped = request.prepare()
            signature = f'{http_method}\n{prepped.body}\n{now.isoformat()}'
            ciphertext = hmac.new(webhook.webhook_secret, signature, digestmod=hashlib.sha3_512)
            prepped.headers['X-Signature'] = ciphertext.hexdigest()
            with requests.Session() as session:
                session.send(prepped)

        except Exception as err:
            logger.exception(err)
            continue
