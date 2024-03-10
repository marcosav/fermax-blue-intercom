from typing import Optional, Dict

import asyncio
import json
import logging
import argparse
import datetime
import os
import httpx

from types import SimpleNamespace

LOGGER = logging.getLogger("fermax_blue")

CACHE_FILENAME = "portal_cache.json"

script_dir = os.path.dirname(os.path.abspath(__file__))
cache_file_path = os.path.join(script_dir, CACHE_FILENAME)


class OAuthTokenResponse:
    access_token: str
    token_type: str
    refresh_token: str
    expires_in: int
    scope: str
    jti: str


class TokenData:

    def __init__(
        self, access_token: str, refresh_token: str, expires_at: datetime.datetime
    ):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at


class AuthError(Exception):
    pass


class NoPairingsError(Exception):
    pass


class BlueClient:

    # Fake client app and iOS device
    COMMON_HEADERS = {
        "app-version": "3.2.1",
        "accept-language": "en-ES;q=1.0, es-ES;q=0.9, ru-ES;q=0.8",
        "phone-os": "16.4",
        "user-agent": "Blue/3.2.1 (com.fermax.bluefermax; build:3; iOS 16.4.0) Alamofire/3.2.1",
        "phone-model": "iPad14,5",
        "app-build": "3",
    }

    AUTH_URL = "https://oauth.blue.fermax.com/oauth/token"
    BASE_URL = "https://blue.fermax.com"

    AUTH_HEADERS = {
        "Authorization": "Basic ZHB2N2lxejZlZTVtYXptMWlxOWR3MWQ0MnNseXV0NDhrajBtcDVmdm81OGo1aWg6Yzd5bGtxcHVqd2FoODV5aG5wcnYwd2R2eXp1dGxjbmt3NHN6OTBidWxkYnVsazE=",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    AUTH_HEADERS.update(COMMON_HEADERS)

    def __init__(self, cache: bool = True):
        self._cache = cache

        self._token_data: Optional[TokenData] = None

        if self._cache:
            self._load_cached_token()

    def _save_token(self, token_data: TokenData):
        with open(cache_file_path, "w") as file:
            json.dump(token_data.__dict__, file, default=self._datetime_handler)

    def _load_cached_token(self):
        try:
            with open(cache_file_path, "r") as file:
                cached_content = json.load(file)
                cached_content["expires_at"] = datetime.datetime.fromisoformat(
                    cached_content["expires_at"]
                )

                self._token_data = TokenData(**cached_content)

        except FileNotFoundError:
            LOGGER.info("Cache file not found")

        except:
            LOGGER.info("There was some error while reading cache file")

    def needs_refresh(self):
        return (
            not self._token_data
            or datetime.datetime.utcnow() >= self._token_data.expires_at
        )

    @staticmethod
    def _datetime_handler(obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    async def auth(self, username: str, password: str):
        LOGGER.info("Logging in into Blue...")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.AUTH_URL,
                headers=self.AUTH_HEADERS,
                data={
                    "grant_type": "password",
                    "username": username,
                    "password": password,
                },
            )

        self._handle_oauth_response(response)

    async def refresh_token(self):
        LOGGER.info("Refreshing session...")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.AUTH_URL,
                headers=self.AUTH_HEADERS,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self._token_data.refresh_token,
                },
            )

        self._handle_oauth_response(response)

    def needs_auth(self):
        return not self._token_data

    def _parse_token(self, response: OAuthTokenResponse) -> TokenData:
        now = datetime.datetime.utcnow()

        return TokenData(
            access_token=response.access_token,
            refresh_token=response.refresh_token,
            expires_at=now + datetime.timedelta(seconds=response.expires_in),
        )

    def _handle_oauth_response(self, response: httpx.Response):
        if response.is_success:
            oauth_response = json.loads(
                response.text, object_hook=lambda d: SimpleNamespace(**d)
            )

            token_data = self._parse_token(oauth_response)

            self._token_data = token_data

            if self._cache:
                self._save_token(token_data)

        elif response.is_client_error:
            parsed_response = response.json()
            raise AuthError(
                f'{parsed_response["error"]} - {parsed_response.get("error_description", "")}'
            )

        else:
            raise AuthError(
                f"Server error - {response.status_code} - {response.content}"
            )

    def _get_json_headers(self) -> Dict[str, str]:
        bearer_token = f"Bearer {self._token_data.access_token}"

        headers = {
            "Authorization": bearer_token,
            "Content-Type": "application/json",
            **self.COMMON_HEADERS,
        }

        return headers

    async def pairings(self) -> tuple:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/pairing/api/v3/pairings/me",
                headers=self._get_json_headers(),
            )

        parsed_json = response.json()

        if not parsed_json:
            raise NoPairingsError()

        pairing = parsed_json[0]
        tag = pairing["tag"]
        device_id = pairing["deviceId"]
        access_door_map = pairing["accessDoorMap"]

        access_ids = []
        for d in access_door_map.values():
            if d["visible"]:
                access_ids.append(d["accessId"])

        return tag, device_id, access_ids

    async def directed_opendoor(self, device_id: str, access_id: str) -> str:
        data = json.dumps(access_id)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.BASE_URL}/deviceaction/api/v1/device/{device_id}/directed-opendoor",
                headers=self._get_json_headers(),
                data=data,
            )

        return response.text


async def main() -> None:

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--username", type=str, help="Fermax Blue account username", required=True
    )
    parser.add_argument(
        "--password", type=str, help="Fermax Blue account password", required=True
    )
    parser.add_argument(
        "--deviceId",
        type=str,
        help="Optional deviceId to avoid extra fetching (requires accessId)",
    )
    parser.add_argument(
        "--accessId",
        type=str,
        nargs="+",
        help="Optional accessId(s) to avoid extra fetching (use with deviceId)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_false",
        dest="cache",
        help="Disables auth token cache usage (read/write)",
    )
    parser.add_argument(
        "--reauth",
        action="store_true",
        help="Forces authentication refresh (when using this option no door will be open)",
    )
    args = parser.parse_args()

    username = args.username
    password = args.password
    device_id = args.deviceId
    access_ids = args.accessId
    cache = args.cache
    reauth = args.reauth

    if (device_id and not access_ids) or (access_ids and not device_id):
        raise Exception("Both deviceId and accessId must be provided")

    provided_doors = device_id and access_ids

    if provided_doors:
        access_ids = [json.loads(access_id) for access_id in access_ids]

    client = BlueClient(cache)

    if client.needs_auth():
        await client.auth(username, password)

    elif client.needs_refresh():
        await client.refresh_token()

    if reauth:
        exit()

    if not provided_doors:
        LOGGER.info("Success, getting devices...")

        tag, device_id, access_ids = client.pairings()

        LOGGER.info(
            f"Found {tag} with deviceId {device_id} ({len(access_ids)} doors), calling directed opendoor..."
        )

    else:
        LOGGER.info(
            f"Success, using provided deviceId {device_id}, calling directed opendoor..."
        )

    # If user provided doors we open them all
    if provided_doors:
        for access_id in access_ids:
            result = await client.directed_opendoor(device_id, access_id)
            LOGGER.info(f"Result: {result}")

    # Otherwise we just open the first one (ZERO?)
    else:
        result = await client.directed_opendoor(device_id, access_ids[0])
        LOGGER.info(f"Result: {result}")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
