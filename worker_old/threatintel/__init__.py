from datetime import datetime, timedelta
from urllib.parse import urlparse
import time
import argparse
import subprocess
import socketio


STATE_IDLE = 'idle'
STATE_STARTING = 'starting'
STATE_PROCESSING = 'processing'
STATE_ERROR = 'error'
STATE_ABORT = 'abort'

sio = socketio.Client()
logger.configure(log_level=config.log_level)
logger.create_stream_logger()
logger.create_file_logger(file_path=config.log_file)

@sio.event
def connect():
    log.info("connected")

@sio.event
def connect_error():
    log.info("connection failed")

@sio.event
def disconnect():
    log.info("disconnected")

def send_event(event :str, data :dict, namespace :str = None):
    if not sio.connected:
        sio.connect(config.socket_url)
    sio.emit(event, data, namespace=namespace)

def get_customer_domains(domain_name):
    limit = 1000
    offset = 0
    ret = set()
    while True:
        domains = Domains().find_by([('name', domain_name), ('deleted', 0)], limit=limit, offset=offset)
        if len(domains) == 0:
            break
        for domain in domains:
            ret.add(domain)
        offset += limit
    return ret

def get_customer_ips(ip_address):
    limit = 1000
    offset = 0
    ret = set()
    while True:
        known_ips = KnownIPs().find_by([('ip_address', ip_address)], limit=limit, offset=offset)
        if len(known_ips) == 0:
            break
        for known_ip in known_ips:
            ret.add(known_ip)
        offset += limit
    return ret

def ipv4_dataplane(feed: Feed, content :str):
    for l in content.splitlines():
        line = l.strip()
        if line.startswith('#') or line.startswith('//') or line == '':
            continue
        _, _, ipaddr, utc, category = line.split('|')
        ipaddr = ipaddr.strip()
        utc = utc.strip()
        category = category.strip()

        for ip_address in cidr_address_list(ipaddr):
            if helpers.is_valid_ipv4_address(ip_address):
                customer_ips = get_customer_ips(ip_address)
                for known_ip in customer_ips:
                    desc = f'{ip_address} since {utc}, source: {feed.name}'
                    alert = SecurityAlert(account_id=known_ip.account_id, type=feed.alert_title, description=desc)
                    if not alert.exists([('account_id', known_ip.account_id), ('description', desc)]):
                        alert.persist()

def ipv4_haleys(feed: Feed, content :str):
    for l in content.splitlines():
        line = l.strip()
        if line.startswith('#') or line.startswith('//') or line == '':
            continue
        if ' : ' in line:
            _, ipaddr_line = line.split(' : ')
            ipaddr, date_line = ipaddr_line.split(' # ')
        else:
            ipaddr, date_line = line.split(' # ')

        timestamp, *_ = date_line.split()
        timestamp = int(timestamp.strip())
        ipaddr = ipaddr.strip()
        occurred_date = datetime.fromtimestamp(timestamp)

        for ip_address in cidr_address_list(ipaddr):
            if helpers.is_valid_ipv4_address(ip_address):
                customer_ips = get_customer_ips(ip_address)
                for known_ip in customer_ips:
                    desc = f'{ip_address} {feed.alert_title} since {occurred_date.isoformat()}, source: {feed.name}'
                    alert = SecurityAlert(account_id=known_ip.account_id, type=feed.alert_title, description=desc)
                    if not alert.exists([('account_id', known_ip.account_id), ('description', desc)]):
                        alert.persist()

def ipv4_list(feed: Feed, content :str):
    for l in content.splitlines():
        ipaddr = l.strip()
        if ipaddr.startswith('#') or ipaddr.startswith('//') or ipaddr == '':
            continue
        for ip_address in cidr_address_list(ipaddr):
            if helpers.is_valid_ipv4_address(ip_address):
                customer_ips = get_customer_ips(ip_address)
                for known_ip in customer_ips:
                    desc = f'{ip_address} {feed.alert_title}, source: {feed.name}'
                    alert = SecurityAlert(account_id=known_ip.account_id, type=feed.alert_title, description=desc)
                    if not alert.exists([('account_id', known_ip.account_id), ('description', desc)]):
                        alert.persist()

def ipv4_bruteforceblocker(feed: Feed, content :str):
    for l in content.splitlines():
        line = l.strip()
        if line.startswith('#') or line.startswith('//') or line == '':
            continue

        ipaddr, *_ = line.split('#')
        ipaddr = ipaddr.strip()
        for ip_address in cidr_address_list(ipaddr):
            if helpers.is_valid_ipv4_address(ip_address):
                customer_ips = get_customer_ips(ip_address)
                for known_ip in customer_ips:
                    desc = f'{ip_address} {feed.alert_title}, source: {feed.name}'
                    alert = SecurityAlert(account_id=known_ip.account_id, type=feed.alert_title, description=desc)
                    if not alert.exists([('account_id', known_ip.account_id), ('description', desc)]):
                        alert.persist()

def csv_malwaredomains(feed: Feed, content :str):
    for l in content.splitlines():
        line = l.strip()
        if line.startswith('#') or line.startswith('//') or line == '':
            continue
        host, threat, original_reference, *_ = [splits.strip() for splits in line.split("\t") if splits.strip() != ""]
        customer_domains = get_customer_domains(host)
        for domain in customer_domains:
            desc = f'{host} - threat {threat}, original reference: {original_reference}, source: {feed.name}'
            alert = SecurityAlert(account_id=domain.account_id, type=feed.alert_title, description=desc)
            if not alert.exists([('account_id', domain.account_id), ('description', desc)]):
                alert.persist()

def url_list(feed: Feed, content :str):
    for l in content.splitlines():
        url = l.strip()
        if url.startswith('#') or url.startswith('//') or url == '':
            continue
        url = url.strip()
        parsed_uri = urlparse(url)
        host = parsed_uri.netloc
        customer_domains = get_customer_domains(host)
        for domain in customer_domains:
            desc = f'{url} {feed.alert_title}, source: {feed.name}'
            alert = SecurityAlert(account_id=domain.account_id, type=feed.alert_title, description=desc)
            if not alert.exists([('account_id', domain.account_id), ('description', desc)]):
                alert.persist()

def csv_urlhaus(feed: Feed, content :str):
    for l in content.splitlines():
        line = l.strip()
        if line.startswith('#') or line.startswith('//') or line == '':
            continue
        try:
            date_added, url, _, threat, host, ipaddr, _, country = line.split('","')
        except ValueError as err:
            log.exception(err)
            log.error(line)
            continue
        date_added = date_added.replace('"', '')
        url = url.replace('"', '')
        threat = threat.replace('"', '')
        host = host.replace('"', '')
        ipaddr = ipaddr.replace('"', '')
        country = country.replace('"', '')

        for ip_address in cidr_address_list(ipaddr):
            if helpers.is_valid_ipv4_address(ip_address) or helpers.is_valid_ipv6_address(ip_address):
                customer_ips = get_customer_ips(ip_address)
                for known_ip in customer_ips:
                    desc = f'{ip_address} {threat} since {date_added} in {country} [{url}] source: {feed.name}'
                    alert = SecurityAlert(account_id=known_ip.account_id, type=feed.alert_title, description=desc)
                    if not alert.exists([('account_id', known_ip.account_id), ('description', desc)]):
                        alert.persist()

        if not helpers.is_valid_ipv4_address(host) and not helpers.is_valid_ipv6_address(host):
            customer_domains = get_customer_domains(host)
            for domain in customer_domains:
                desc = f'{host} {threat} since {date_added} in {country} [{url}] source: {feed.name}'
                alert = SecurityAlert(account_id=domain.account_id, type=feed.alert_title, description=desc)
                if not alert.exists([('account_id', domain.account_id), ('description', desc)]):
                    alert.persist()

def rss_projecthoneypot(feed: Feed, content :str, file_path :str):
    log.info(f'feed {feed.type}')
    log.info(f'file_path {file_path}')

def rss_hphosts(feed: Feed, content :str, file_path :str):
    log.info(f'feed {feed.type}')
    log.info(f'file_path {file_path}')

def rss1_callbackdomains(feed: Feed, content :str, file_path :str):
    log.info(f'feed {feed.type}')
    log.info(f'file_path {file_path}')

def rss2_malc0de(feed: Feed, content :str, file_path :str):
    log.info(f'feed {feed.type}')
    log.info(f'file_path {file_path}')

def json_gz(feed: Feed, content :str, file_path :str):
    log.info(f'feed {feed.type}')
    log.info(f'file_path {file_path}')

def update_service_state(service: Service, state :str, event_desc :str):
    data = {
        'nodes': sum(1 for s in Services().find_by([('category', service.category)], limit=1000) if s.updated_at > datetime.utcnow() - timedelta(minutes=5)),
        'queued_jobs': Feeds().num_queued(category='threat_intel'),
        'running_jobs': Feeds().num_running(category='threat_intel'),
        'errored_jobs': Feeds().num_errored(category='threat_intel')
    }
    data['service'] = service.category
    data['state'] = state
    data['last_event'] = event_desc
    service.state = state
    service.updated_at = datetime.utcnow().isoformat()
    service.persist()
    send_event('update_service_state', data)

def main(opts :dict, service: Service):
    log.info(f'checking queue for service {opts.service}')
    check_feeds = Feeds().get_queued('threat_intel', limit=10)
    if not check_feeds:
        return
    log.info(f'Processing {len(check_feeds)} Feeds')
    update_service_state(service, STATE_PROCESSING, 'starting')

    for feed in check_feeds:
        code, status = helpers.http_status(feed.url)
        feed.http_status = status
        feed.http_code = code
        feed.persist()

        keepcharacters = ('.', '_', '-')
        temp_name = "".join(c for c in feed.name if c.isalnum() or c in keepcharacters).strip()
        update_service_state(service, STATE_PROCESSING, feed.url)
        file_path, cached = helpers.download_file(remote_file=feed.url, temp_name=temp_name, temp_dir=config.app_tmp_dir)
        if cached:
            log.info('cached')
            continue
        if not file_path:
            log.warning(f'file_path not set')
            continue
        fd = open(file_path, 'r')
        content = fd.read()
        fd.close()

        update_service_state(service, STATE_PROCESSING, feed.type)
        if feed.type == 'ipv4_dataplane':
            ipv4_dataplane(feed, content, file_path)
        if feed.type == 'ipv4_haleys':
            ipv4_haleys(feed, content, file_path)
        if feed.type == 'ipv4_list':
            ipv4_list(feed, content, file_path)
        if feed.type == 'ipv4_bruteforceblocker':
            ipv4_bruteforceblocker(feed, content, file_path)
        if feed.type == 'json_gz':
            json_gz(feed, content, file_path)
        if feed.type == 'rss2.0_malc0de':
            rss2_malc0de(feed, content, file_path)
        if feed.type == 'csv_malwaredomains':
            csv_malwaredomains(feed, content, file_path)
        if feed.type == 'url_list':
            url_list(feed, content, file_path)
        if feed.type == 'csv_urlhaus':
            csv_urlhaus(feed, content, file_path)
        if feed.type == 'rss_projecthoneypot':
            rss_projecthoneypot(feed, content, file_path)
        if feed.type == 'rss_hphosts':
            rss_hphosts(feed, content, file_path)
        if feed.type == 'rss1.0_callbackdomains':
            rss1_callbackdomains(feed, content, file_path)

        feed.last_checked = datetime.utcnow().isoformat()
        feed.persist()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--service', help='service instance', dest='service', required=True)
    parser.add_argument('-l', '--log-file', help='absolution path to the application log file', dest='log_file', default='/tmp/application.log')
    args = parser.parse_args()
    proc = subprocess.run('cat /etc/hostname', shell=True, capture_output=True)
    node_id = proc.stdout.decode('utf-8').strip()
    err = proc.stderr.decode('utf-8')
    if err:
        log.warning(err)
    if not node_id or len(node_id) != 12:
        log.error(f'hostname could not be found, got [{node_id}]')
        exit(1)

    service = Service(node_id=node_id)
    service.name = args.service
    service.category = args.service
    service.state = STATE_IDLE
    update_service_state(service, STATE_STARTING, 'starting')
    main(args, service)
    update_service_state(service, STATE_IDLE, 'restarting..')
    time.sleep(1)
    sio.disconnect()
