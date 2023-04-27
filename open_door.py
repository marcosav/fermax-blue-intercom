import requests
import json
import logging
import argparse
import datetime
import os
import time

from urllib.parse import quote


# Input values

parser = argparse.ArgumentParser()
parser.add_argument('--username', type=str,
                    help='Fermax Blue account username', required=True)
parser.add_argument('--password', type=str,
                    help='Fermax Blue account password', required=True)
parser.add_argument('--deviceId', type=str,
                    help='Optional deviceId to avoid extra fetching (requires accessId)')
parser.add_argument('--accessId', type=str, nargs='+',
                    help='Optional accessId(s) to avoid extra fetching (use with deviceId)')
parser.add_argument('--cache', type=bool,
                    help='Optionally set if cache is used to save auth token (enabled by default)', default=True)
args = parser.parse_args()

username = args.username
password = args.password
deviceId = args.deviceId
accessIds = args.accessId
cache = args.cache

if (deviceId and not accessIds) or (accessIds and not deviceId):
    raise Exception('Both deviceId and accessId must be provided')

provided_doors = deviceId and accessIds

if provided_doors:
    accessIds = list(map(lambda accessId: json.loads(accessId), accessIds))


CACHE_FILENAME = 'portal_cache.json'
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

script_dir = os.path.dirname(os.path.abspath(__file__))
cache_file_path = os.path.join(script_dir, CACHE_FILENAME)


def update_cached_token(access_token: str, max_age: int):
    logging.info('Caching token...')

    current_datetime = datetime.datetime.now().strftime(DATETIME_FORMAT)

    cached_content = {
        'access_token': access_token,
        'max_age': max_age,
        'updated_at': current_datetime,
    }

    with open(cache_file_path, 'w') as file:
        json.dump(cached_content, file)


def read_cached_token() -> str:
    try:
        with open(cache_file_path, 'r') as file:
            cached_content = json.load(file)

            access_token = cached_content['access_token']
            max_age = cached_content['max_age']
            cache_datetime = datetime.datetime.strptime(
                cached_content['updated_at'], DATETIME_FORMAT)

        current_age = datetime.datetime.now() - cache_datetime
        if current_age.total_seconds() >= max_age:
            logging.info('Cached token has expired')
            return None
        else:
            return access_token
    except FileNotFoundError:
        logging.info('Cache file not found')
        return None


# Fake client app and iOS device
COMMON_HEADERS = {
    'app-version': '3.2.1',
    'accept-language': 'en-ES;q=1.0, es-ES;q=0.9, ru-ES;q=0.8',
    'phone-os': '16.4',
    'user-agent': 'Blue/3.2.1 (com.fermax.bluefermax; build:3; iOS 16.4.0) Alamofire/3.2.1',
    'phone-model': 'iPad14,5',
    'app-build': '3'
}


AUTH_URL = 'https://oauth.blue.fermax.com/oauth/token'

AUTH_HEADERS = {
    'Authorization': 'Basic ZHB2N2lxejZlZTVtYXptMWlxOWR3MWQ0MnNseXV0NDhrajBtcDVmdm81OGo1aWg6Yzd5bGtxcHVqd2FoODV5aG5wcnYwd2R2eXp1dGxjbmt3NHN6OTBidWxkYnVsazE=',
    'Content-Type': 'application/x-www-form-urlencoded'
}
AUTH_HEADERS.update(COMMON_HEADERS)


def auth(cache: bool, username: str, password: str) -> str:
    username = quote(username)
    auth_payload = f'grant_type=password&password={password}&username={username}'

    response = requests.request(
        'POST', AUTH_URL, headers=AUTH_HEADERS, data=auth_payload)

    parsed_json = response.json()
    if 'error' in parsed_json:
        raise RuntimeError(parsed_json['error_description'])
        
    
    access_token = parsed_json['access_token']
    max_age = parsed_json['expires_in']

    if cache:
        update_cached_token(access_token, max_age)

    return access_token


def get_json_headers(bearer_token: str) -> str:
    headers = {'Authorization': bearer_token,
               'Content-Type': 'application/json'}
    headers.update(COMMON_HEADERS)

    return headers


PAIRINGS_URL = 'https://blue.fermax.com/pairing/api/v3/pairings/me'


def pairings(bearer_token: str) -> tuple:
    response = requests.request(
        'GET', PAIRINGS_URL, headers=get_json_headers(bearer_token), data={})

    parsed_json = response.json()

    if not parsed_json:
        raise Exception('There are no pairings')

    pairing = parsed_json[0]
    tag = pairing['tag']
    deviceId = pairing['deviceId']
    accessDoorMap = pairing['accessDoorMap']

    accessIds = []
    for d in accessDoorMap.values():
        if d['visible']:
            accessIds.append(d['accessId'])

    return (tag, deviceId, accessIds)


def directed_opendoor(bearer_token: str, deviceId: str, accessId: str) -> str:
    directed_opendoor_url = f'https://blue.fermax.com/deviceaction/api/v1/device/{deviceId}/directed-opendoor'

    payload = json.dumps(accessId)

    response = requests.request(
        'POST', directed_opendoor_url, headers=get_json_headers(bearer_token), data=payload)

    return response.text


# Program

access_token = None

if cache:
    access_token = read_cached_token()

if not access_token:
    logging.info('Logging in into Blue...')

    access_token = auth(cache, username, password)

bearer_token = f'Bearer {access_token}'

if not provided_doors:
    logging.info('Success, getting devices...')

    tag, deviceId, accessIds = pairings(bearer_token)

    logging.info(
        f'Found {tag} with deviceId {deviceId} ({len(accessIds)} doors), calling directed opendoor...')

else:
    logging.info(
        f'Success, using provided deviceId {deviceId}, calling directed opendoor...')

# If user provided doors we open them all
if provided_doors:
    for accessId in accessIds:
        result = directed_opendoor(bearer_token, deviceId, accessId)
        logging.info(f'Result: {result}')
        time.sleep(7)

# Otherwise we just open the first one (ZERO?)
else:
    result = directed_opendoor(bearer_token, deviceId, accessIds[0])
    logging.info(f'Result: {result}')