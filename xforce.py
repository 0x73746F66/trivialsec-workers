import json
import logging
import pathlib
from random import randint
from time import sleep
from datetime import datetime, timedelta
import requests
from retry.api import retry
from requests.exceptions import ConnectTimeout, ReadTimeout


logger = logging.getLogger(__name__)
logging.basicConfig(
    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s',
    level=logging.INFO
)

class Config:
    http_proxy = None
    https_proxy = None

config = Config()
PROXIES = None
if config.http_proxy or config.https_proxy:
    PROXIES = {
        'http': f'http://{config.http_proxy}',
        'https': f'https://{config.https_proxy}'
    }
BASE_URL = 'https://exchange.xforce.ibmcloud.com'
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
DATAFILE_DIR = 'datafiles/xforce/vulnerabilities'
v2_0 = {
    'E': {
        'High': 'E:H',
        'Functional': 'E:F',
        'Proof-of-Concept': 'E:POC',
        'Unproven': 'E:U',
    },
    'RL': {
        'Official Fix': 'RL:OF',
        'Temporary Fix': 'RL:TF',
        'Workaround': 'RL:W',
        'Unavailable': 'RL:U',
    },
    'RC': {
        'Unconfirmed': 'RC:UC',
        'Uncorroborated': 'RC:UR',
        'Confirmed': 'RC:C',
    }
}

@retry((ConnectTimeout, ReadTimeout), tries=10, delay=30, backoff=5)
def query_single(ref_id :int):
    api_url = f'{BASE_URL}/api/vulnerabilities/{ref_id}'
    logger.info(api_url)
    resp = requests.get(
        api_url,
        proxies=PROXIES,
        headers={
            'x-ui': "XFE",
            'User-Agent': USER_AGENT,
            'origin': BASE_URL
        },
        timeout=10
    )
    if resp.status_code != 200:
        logger.info(f'{resp.status_code} {api_url}')

    return resp.text

def xforce_cvss_vector(obj :dict):
    if 'cvss' not in obj:
        return None
    vector = ''
    if obj['cvss']['version'] in ['1.0', '2.0']:
        if 'access_vector' in obj['cvss']:
            vector += f"AV:{obj['cvss']['access_vector'][:1].upper()}/"
        if 'access_complexity' in obj['cvss']:
            vector += f"AC:{obj['cvss']['access_complexity'][:1].upper()}/"
        if 'authentication' in obj['cvss']:
            vector += f"Au:{obj['cvss']['authentication'][:1].upper()}/"
        if 'confidentiality_impact' in obj['cvss']:
            vector += f"C:{obj['cvss']['confidentiality_impact'][:1].upper()}/"
        if 'integrity_impact' in obj['cvss']:
            vector += f"I:{obj['cvss']['integrity_impact'][:1].upper()}/"
        if 'availability_impact' in obj['cvss']:
            vector += f"A:{obj['cvss']['availability_impact'][:1].upper()}/"
    if obj['cvss']['version'] in ['3.0', '3.1']:
        if 'access_vector' in obj['cvss']:
            vector += f"AV:{obj['cvss']['access_vector'][:1].upper()}/"
        if 'access_complexity' in obj['cvss']:
            vector += f"AC:{obj['cvss']['access_complexity'][:1].upper()}/"
        if 'privilegesrequired' in obj['cvss']:
            vector += f"PR:{obj['cvss']['privilegesrequired'][:1].upper()}/"
        if 'userinteraction' in obj['cvss']:
            vector += f"UI:{obj['cvss']['userinteraction'][:1].upper()}/"
        if 'scope' in obj['cvss']:
            vector += f"S:{obj['cvss']['scope'][:1].upper()}/"
        if 'confidentiality_impact' in obj['cvss']:
            vector += f"C:{obj['cvss']['confidentiality_impact'][:1].upper()}/"
        if 'integrity_impact' in obj['cvss']:
            vector += f"I:{obj['cvss']['integrity_impact'][:1].upper()}/"
        if 'availability_impact' in obj['cvss']:
            vector += f"A:{obj['cvss']['availability_impact'][:1].upper()}/"
        if 'exploitability' in obj:
            exploitability = obj['exploitability'][:1].upper()
            vector += 'E:X/' if exploitability not in ['U', 'P', 'F', 'H'] else f'E:{exploitability}/'
        if 'remediation_level' in obj['cvss']:
            remediation_level = obj['cvss']['remediation_level'][:1].upper()
            vector += 'RL:X/' if remediation_level not in ['O', 'T', 'W', 'U'] else f'RL:{remediation_level}/'
        if 'report_confidence' in obj:
            report_confidence = obj['report_confidence'][:1].upper()
            vector += 'RC:X' if report_confidence not in ['U', 'R', 'C'] else f'RC:{report_confidence}'
    if obj['cvss']['version'] == '2.0':
        if 'exploitability' in obj:
            vector += 'E:ND/' if obj['exploitability'] not in v2_0['E'] else f"{v2_0['E'][obj['exploitability']]}/"
        if 'remediation_level' in obj['cvss']:
            vector += 'RL:ND/' if obj['cvss']['remediation_level'] not in v2_0['RL'] else f"{v2_0['RL'][obj['cvss']['remediation_level']]}/"
        if 'report_confidence' in obj:
            vector += 'RC:ND' if obj['report_confidence'] not in v2_0['RC'] else f"{v2_0['RC'][obj['report_confidence']]}"

    return vector

@retry((ConnectTimeout, ReadTimeout), tries=10, delay=30, backoff=5)
def query_bulk(start :datetime, end :datetime):
    response = None
    api_url = f'{BASE_URL}/api/vulnerabilities/fulltext?q=vulnerability&startDate={start.isoformat()}Z&endDate={end.isoformat()}Z'
    logger.info(api_url)
    resp = requests.get(
        api_url,
        proxies=PROXIES,
        headers={
            'x-ui': "XFE",
            'User-Agent': USER_AGENT,
            'origin': BASE_URL
        },
        timeout=10
    )
    if resp.status_code != 200:
        logger.info(f'{resp.status_code} {api_url}')
        return response

    raw = resp.text
    if raw is None or not raw:
        logger.info(f'empty response {api_url}')

    try:
        response = json.loads(raw)
    except json.decoder.JSONDecodeError as ex:
        logger.exception(ex)
        logger.info(raw)

    return response

@retry((ConnectTimeout, ReadTimeout), tries=10, delay=30, backoff=5)
def query_latest(limit :int = 200):
    response = []
    api_url = f'{BASE_URL}/api/vulnerabilities/?limit={limit}'
    resp = requests.get(
        api_url,
        proxies=PROXIES,
        headers={
            'x-ui': "XFE",
            'User-Agent': USER_AGENT,
            'origin': BASE_URL
        },
        timeout=10
    )
    if resp.status_code != 200:
        logger.info(f'{resp.status_code} {api_url}')
    raw = resp.text
    if raw is None or not raw:
        logger.info(f'empty response {api_url}')

    try:
        response = json.loads(raw)
    except json.decoder.JSONDecodeError as ex:
        logger.exception(ex)
        logger.info(raw)

    return response

def do_latest(limit :int):
    for item in query_latest(limit):
        original_data = {}
        xforce_file = pathlib.Path(f"{DATAFILE_DIR}/{item['xfdbid']}.json")
        if xforce_file.is_file():
            original_data = json.loads(xforce_file.read_text())
            original_data |= item
            original_data['cvss_vector'] = xforce_cvss_vector(original_data)
            xforce_file.write_text(json.dumps(original_data, default=str, sort_keys=True))
            continue

        item['cvss_vector'] = xforce_cvss_vector(item)
        xforce_file.write_text(json.dumps(item, default=str, sort_keys=True))

def do_bulk(start :datetime, end :datetime) -> bool:
    resp = query_bulk(start, end)
    total_rows = int(resp.get('total_rows', 0))
    logger.info(f'total_rows {total_rows}')
    if total_rows == 0:
        logger.info(f'no data between {start} and {end}')
        return False
    if total_rows > 200:
        midday = datetime(start.year, start.month, start.day, 12)
        bulk1 = query_bulk(start, midday)
        rows = bulk1.get('rows', [])
        bulk2 = query_bulk(midday, end)
        rows += bulk2.get('rows', [])
    if total_rows <= 200:
        rows = resp.get('rows', [])
    for item in rows:
        datafile = f"{DATAFILE_DIR}/{item['xfdbid']}.json"
        original_data = {}
        xforce_file = pathlib.Path(datafile)
        if xforce_file.is_file():
            logger.debug(datafile)
            original_data = json.loads(xforce_file.read_text())
            original_data |= item
            original_data['cvss_vector'] = xforce_cvss_vector(original_data)
            xforce_file.write_text(json.dumps(original_data, default=str, sort_keys=True))
            continue

        logger.info(datafile)
        item['cvss_vector'] = xforce_cvss_vector(item)
        xforce_file.write_text(json.dumps(item, default=str, sort_keys=True))
    return True

def read_file(file_path :str):
    bulk_file = pathlib.Path(file_path)
    if bulk_file.is_file():
        for item in json.loads(bulk_file.read_text()):
            datafile = f"{DATAFILE_DIR}/{item['xfdbid']}.json"
            logger.debug(datafile)
            xforce_file = pathlib.Path(datafile)
            if xforce_file.is_file():
                original_data = json.loads(xforce_file.read_text())
                original_data |= item
                original_data['cvss_vector'] = xforce_cvss_vector(original_data)
                xforce_json = json.dumps(original_data, default=str, sort_keys=True)
                xforce_file.write_text(xforce_json)
                continue

            item['cvss_vector'] = xforce_cvss_vector(item)
            xforce_json = json.dumps(item, default=str, sort_keys=True)
            xforce_file.write_text(xforce_json)

def query_all_individually():
    next_id = 1
    while next_id < 206792:
        original_data = {}
        xforce_file = pathlib.Path(f"{DATAFILE_DIR}/{next_id}.json")
        if xforce_file.is_file():
            original_data = json.loads(xforce_file.read_text())
            original_data['cvss_vector'] = xforce_cvss_vector(original_data)
            xforce_file.write_text(json.dumps(original_data, default=str, sort_keys=True))
            next_id += 1
            continue

        try:
            raw = query_single(next_id)
            if raw is None:
                next_id += 1
                continue
            response = json.loads(raw)
            response['cvss_vector'] = xforce_cvss_vector(response)
            xforce_file.write_text(json.dumps(response, default=str, sort_keys=True))
        except json.decoder.JSONDecodeError as ex:
            logger.exception(ex)
            logger.info(raw)
        next_id += 1

def main():
    not_before = datetime(1996, 12, 31)
    # now = datetime.utcnow()
    # end = datetime(now.year, now.month, now.day)
    end = datetime(2011, 6, 18)
    start = end - timedelta(days=1)
    while start > not_before:
        logger.info(f'between {start} and {end}')
        do_bulk(start, end)
        end = start
        start = end - timedelta(days=1)
        sleep(randint(3,6))

if __name__ == "__main__":
    # read_file("xforce-response.json")
    main()
