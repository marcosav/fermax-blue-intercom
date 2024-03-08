from typing import Optional, Dict

import requests
import json
import logging
import argparse
import datetime
import os
import time

from urllib.parse import quote

from types import SimpleNamespace

LOGGER = logging.getLogger("fermax_blue")

CACHE_FILENAME = 'portal_cache.json'

script_dir = os.path.dirname(os.path.abspath(__file__))
cache_file_path = os.path.join(script_dir, CACHE_FILENAME)


class OAuthTokenResponse():
    access_token: str
    token_type: str
    refresh_token: str
    expires_in: int
    scope: str
    jti: str
    
    
class CachedTokenData():
    def __init__(self, access_token: str, refresh_token: str, expires_at: datetime.datetime):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at


def update_cached_token(response: OAuthTokenResponse):
    LOGGER.info('Caching token...')

    now = datetime.datetime.utcnow()

    cached_content: CachedTokenData = {
        'access_token': response.access_token,
        'refresh_token': response.refresh_token,
        'expires_at': now + datetime.timedelta(seconds=response.expires_in),
    }

    with open(cache_file_path, 'w') as file:
        json.dump(cached_content, file, default=datetime_handler)


def read_cached_token() -> Optional[CachedTokenData]:
    try:
        with open(cache_file_path, 'r') as file:
            cached_content = json.load(file)
            cached_content['expires_at'] = datetime.datetime.fromisoformat(cached_content['expires_at'])
            return CachedTokenData(**cached_content)
        
    except FileNotFoundError:
        LOGGER.info('Cache file not found')
        return None
    
    except:
        LOGGER.info('There was some error while reading cache file')
        return None
    

def should_refresh(cached_token: CachedTokenData):
    return datetime.datetime.utcnow() >= cached_token.expires_at

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


def datetime_handler(obj):
    if isinstance(obj, datetime.datetime): 
        return obj.isoformat() 
    raise TypeError("Type not serializable")
    

def auth(cache: bool, username: str, password: str) -> OAuthTokenResponse:
    username = quote(username)
    password = quote(password)
    auth_payload = f'grant_type=password&password={password}&username={username}'

    response = requests.request(
        'POST', AUTH_URL, headers=AUTH_HEADERS, data=auth_payload)

    parsed_response = response.json()
    if 'error' in parsed_response:
        raise RuntimeError(parsed_response['error_description'])

    oauth_response = json.loads(response.text, object_hook=lambda d: SimpleNamespace(**d))

    if cache:
        update_cached_token(oauth_response)

    return oauth_response


def refresh_token(cache: bool, refresh_token: str) -> OAuthTokenResponse:
    auth_payload = f'grant_type=refresh_token&refresh_token={refresh_token}'
    response = requests.request(
        'POST', AUTH_URL, headers=AUTH_HEADERS, data=auth_payload)
    
    parsed_response = response.json()
    if 'error' in parsed_response:
        raise RuntimeError(parsed_response['error_description'])
    
    oauth_response = json.loads(response.text, object_hook=lambda d: SimpleNamespace(**d))
    
    if cache:
        update_cached_token(oauth_response)
    
    return oauth_response


def get_json_headers(bearer_token: str) -> Dict[str, str]:
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
    device_id = pairing['deviceId']
    access_door_map = pairing['accessDoorMap']

    access_ids = []
    for d in access_door_map.values():
        if d['visible']:
            access_ids.append(d['accessId'])

    return tag, device_id, access_ids


def directed_opendoor(bearer_token: str, device_id: str, access_id: str) -> str:
    directed_opendoor_url = f'https://blue.fermax.com/deviceaction/api/v1/device/{device_id}/directed-opendoor'

    payload = json.dumps(access_id)

    response = requests.request(
        'POST', directed_opendoor_url, headers=get_json_headers(bearer_token), data=payload)

    return response.text


def main() -> None:
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
    parser.add_argument('--no-cache', action='store_false', dest='cache',
                        help='Disables auth token cache usage (read/write)')
    parser.add_argument('--reauth', action='store_true',
                        help='Forces authentication refresh (when using this option no door will be open)')
    args = parser.parse_args()

    username = args.username
    password = args.password
    device_id = args.deviceId
    access_ids = args.accessId
    cache = args.cache
    reauth = args.reauth

    if (device_id and not access_ids) or (access_ids and not device_id):
        raise Exception('Both deviceId and accessId must be provided')

    provided_doors = device_id and access_ids

    if provided_doors:
        access_ids = [json.loads(access_id) for access_id in access_ids]

    # Program

    oauth_token = None

    if cache:
        oauth_token = read_cached_token()

        
    if oauth_token and (reauth or should_refresh(oauth_token)):
        LOGGER.info('Refreshing Blue session...')
        oauth_token = refresh_token(cache, oauth_token.refresh_token)
    else:
        LOGGER.info('Logging in into Blue...')
        oauth_token = auth(cache, username, password)


    bearer_token = f'Bearer {oauth_token.access_token}'


    if reauth:
        exit()


    if not provided_doors:
        LOGGER.info('Success, getting devices...')

        tag, device_id, access_ids = pairings(bearer_token)

        LOGGER.info(
            f'Found {tag} with deviceId {device_id} ({len(access_ids)} doors), calling directed opendoor...')

    else:
        LOGGER.info(
            f'Success, using provided deviceId {device_id}, calling directed opendoor...')


    # If user provided doors we open them all
    if provided_doors:
        for access_id in access_ids:
            result = directed_opendoor(bearer_token, device_id, access_id)
            LOGGER.info(f'Result: {result}')
            time.sleep(7)

    # Otherwise we just open the first one (ZERO?)
    else:
        result = directed_opendoor(bearer_token, device_id, access_ids[0])
        LOGGER.info(f'Result: {result}')


if __name__ == "__main__":
    main()
