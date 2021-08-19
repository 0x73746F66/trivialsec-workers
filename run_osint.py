import csv
import requests
import pandas as pd
from datetime import datetime
from ipwhois import IPWhois
from ipwhois.utils import get_countries
from netaddr import IPAddress


API_KEY = '<maps apikey>'
file_in = "./internet-connected.csv"
file_out = "./enriched-ip-list.csv"


def get_coords(ip):
    url = "https://freegeoip.net/json/%s" % ip
    r = requests.get(url)

    return r.json()


def get_geo(lat, lon):
    url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?key={}&radius=1&location={},{}".format(
        API_KEY, lat, lon)
    r = requests.get(url)

    return r.json()


def get_place(id):
    url = "https://maps.googleapis.com/maps/api/place/details/json?key={}&placeid={}".format(
        API_KEY, id)
    r = requests.get(url)

    return r.json()


def whois(ip):
    countries = get_countries()
    obj = IPWhois(ip)
    result = obj.lookup_rdap(depth=1, asn_methods=['dns', 'whois', 'http'])
    country = countries[result['asn_country_code']]
    network_type = result['network']['type']
    name = result['network']['name']
    description = result['asn_description']
    registry = result['asn_registry']
    entities = ', '.join(result['entities'])

    return country, network_type, name, description, registry, entities


def seconds_to_gmt_offset_str(secs):
    if not isinstance(secs, int):
        return None
    prefix = '+'
    if secs < 0:
        prefix = '-'

    return "%s%02d:%02d" % (prefix, abs(secs) / 60, abs(secs) % 60)


fileReader = csv.reader(open(file_in), delimiter=",")
header = fileReader.next()
for ip in fileReader:
    dt = datetime.utcnow()
    data = whois(ip)
    coords = get_coords(ip)
    geo = get_geo(float(coords['latitude']), float(coords['longitude']))
    placeid = None
    placeurl = None
    address = None
    offset = None
    gmt = None
    if len(geo['results']) > 0:
        placeid = geo['results'][0]['place_id']
        place = get_place(placeid)
        if 'formatted_address' in place['result']:
            address = place['result']['formatted_address']
        if 'url' in place['result']:
            placeurl = place['result']['url']
        if 'utc_offset' in place['result']:
            offset = int(place['result']['utc_offset'])
    if offset:
        gmt = seconds_to_gmt_offset_str(offset)
    if type(gmt) != str:
        gmt = None

    data_dict = {
        'ipaddr': ip,
        'reversedns': IPAddress(ip).reverse_dns,
        'type': data[1],
        'name': data[2],
        'description': data[3],
        'registry': data[4],
        'entities': data[5],
        'country': data[0],
        'city': coords['city'],
        'region': coords['region_name'],
        'address': address,
        'zip': coords['zip_code'],
        'placeid': placeid,
        'url': placeurl,
        'lat': float(coords['latitude']),
        'lon': float(coords['longitude']),
        'tz': coords['time_zone'],
        'utc': offset,
        'gmt': gmt,
        'checked': dt.isoformat()
    }

    df = pd.DataFrame(data_dict, index=[0])
    c = {
        # 'compression': 'gzip',
        'quotechar': '"',
        'quoting': csv.QUOTE_MINIMAL,
        'doublequote': False,
        'index': False,
        'sep': ','
    }
    df.to_csv(file_out, **c)
