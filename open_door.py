from typing import Optional, Dict, List

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


class User:
    def __init__(
        self,
        email: str,
        locale: str,
        accept_sharing: bool,
        accept_privacy: bool,
        enabled: bool,
        created_at: datetime.datetime,
        country: str,
        city: str,
        area: str,
        zone: str,
        subzone: str,
        pin: Optional[str],
        pin_date: Optional[str],
        unique_session: bool,
        provider: Optional[str],
        name: Optional[str],
    ):
        self.email = email
        self.locale = locale
        self.accept_sharing = accept_sharing
        self.accept_privacy = accept_privacy
        self.enabled = enabled
        self.created_at = created_at
        self.country = country
        self.city = city
        self.area = area
        self.zone = zone
        self.subzone = subzone
        self.pin = pin
        self.pin_date = pin_date
        self.unique_session = unique_session
        self.provider = provider
        self.name = name


class AccessId:
    def __init__(self, block: int, subblock: int, number: int):
        self.block = block
        self.subblock = subblock
        self.number = number

    block: int
    subblock: int
    number: int


class AccessDoor:
    def __init__(self, title: str, access_id: AccessId, visible: bool):
        self.title = title
        self.access_id = access_id
        self.visible = visible

    title: str
    access_id: AccessId
    visible: bool


class Pairing:
    def __init__(
        self,
        id: str,
        device_id: str,
        tag: str,
        status: str,
        updated_at: datetime.datetime,
        created_at: datetime.datetime,
        app_build: str,
        app_version: str,
        phone_model: str,
        phone_os: str,
        home: Optional[str],
        address: Optional[str],
        access_door_map: Dict[str, AccessDoor],
        master: bool,
    ):
        self.id = id
        self.device_id = device_id
        self.tag = tag
        self.status = status
        self.updated_at = updated_at
        self.created_at = created_at
        self.app_build = app_build
        self.app_version = app_version
        self.phone_model = phone_model
        self.phone_os = phone_os
        self.home = home
        self.address = address
        self.access_door_map = access_door_map
        self.master = master

    id: str
    device_id: str
    tag: str
    status: str
    updatedAt: int
    createdAt: int
    updated_at: datetime.datetime
    created_at: datetime.datetime
    app_build: str
    app_version: str
    phone_model: str
    phone_os: str
    home: Optional[str]
    address: Optional[str]
    access_door_map: Dict[str, AccessDoor]
    master: bool


class DeviceInfo:
    def __init__(
        self,
        device_id: str,
        connection_state: str,
        status: str,
        installation_id: str,
        family: str,
        type: str,
        subtype: str,
        num_block: int,
        num_subblock: int,
        unit_number: int,
        connectable: bool,
        iccid: str,
        divert_service: str,
        photocaller: bool,
        wireless_signal: int,
        blue_stream: bool,
        phone: bool,
        monitor: bool,
        monitor_or_guard_unit: bool,
        terminal: bool,
        panel_or_edibox: bool,
        panel: bool,
        streaming_mode: str,
    ):
        self.device_id = device_id
        self.connection_state = connection_state
        self.status = status
        self.installation_id = installation_id
        self.family = family
        self.type = type
        self.subtype = subtype
        self.num_block = num_block
        self.num_subblock = num_subblock
        self.unit_number = unit_number
        self.connectable = connectable
        self.iccid = iccid
        self.divert_service = divert_service
        self.photocaller = photocaller
        self.wireless_signal = wireless_signal
        self.blue_stream = blue_stream
        self.phone = phone
        self.monitor = monitor
        self.monitor_or_guard_unit = monitor_or_guard_unit
        self.terminal = terminal
        self.panel_or_edibox = panel_or_edibox
        self.panel = panel
        self.streaming_mode = streaming_mode


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

    AUTH_URL = "https://oauth-pro-duoxme.fermax.io/oauth/token"
    BASE_URL = "https://pro-duoxme.fermax.io"
    # BASE_URL = "https://blue.fermax.io"

    AUTH_HEADERS = {
        "Authorization": "Basic ZHB2N2lxejZlZTVtYXptMWlxOWR3MWQ0MnNseXV0NDhrajBtcDVmdm81OGo1aWg6Yzd5bGtxcHVqd2FoODV5aG5wcnYwd2R2eXp1dGxjbmt3NHN6OTBidWxkYnVsazE=",
        "Content-Type": "application/x-www-form-urlencoded",
    }

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
                expiration_date = datetime.datetime.fromisoformat(cached_content["expires_at"])
                expiration_date = expiration_date.replace(tzinfo=datetime.timezone.utc)
                cached_content["expires_at"] = expiration_date

                self._token_data = TokenData(**cached_content)

        except FileNotFoundError:
            LOGGER.info("Cache file not found")

        except:
            LOGGER.info("There was some error while reading cache file")

    def needs_refresh(self):
        return (
            not self._token_data
            or datetime.datetime.now(tz=datetime.timezone.utc)
            >= self._token_data.expires_at
        )

    @staticmethod
    def _datetime_handler(obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    def _create_http_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=10.0)

    async def auth(self, username: str, password: str):
        LOGGER.info("Logging in into Blue...")

        async with self._create_http_client() as client:
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

        async with self._create_http_client() as client:
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
        now = datetime.datetime.now(tz=datetime.timezone.utc)

        return TokenData(
            access_token=response.access_token,
            refresh_token=response.refresh_token,
            expires_at=now + datetime.timedelta(seconds=response.expires_in),
        )

    def _handle_error_response(self, response: httpx.Response):
        if response.is_client_error:
            parsed_response = response.json()
            raise AuthError(
                f'{parsed_response["error"]} - {parsed_response.get("error_description", "")}'
            )

        else:
            raise AuthError(
                f"Server error - {response.status_code} - {response.content}"
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

        else:
            self._handle_error_response(response)

    def _get_json_headers(self) -> Dict[str, str]:
        bearer_token = f"Bearer {self._token_data.access_token}"

        headers = {
            "Authorization": bearer_token,
            "Content-Type": "application/json",
            **self.COMMON_HEADERS,
        }

        return headers

    @staticmethod
    def _parse_pairings(response: httpx.Response) -> List[Pairing]:
        parsed_json = response.json()

        pairings: List[Pairing] = []
        for p in parsed_json:
            access_door_map = {}

            for k, v in p["accessDoorMap"].items():
                access_id_json = v["accessId"]
                access_id = AccessId(
                    block=access_id_json["block"],
                    subblock=access_id_json["subblock"],
                    number=access_id_json["number"],
                )
                access_door_map[k] = AccessDoor(
                    title=v["title"],
                    access_id=access_id,
                    visible=v["visible"],
                )

            pairing = Pairing(
                id=p["id"],
                device_id=p["deviceId"],
                tag=p["tag"],
                status=p["status"],
                updated_at=datetime.datetime.fromtimestamp(p["updatedAt"] / 1000),
                created_at=datetime.datetime.fromtimestamp(p["createdAt"] / 1000),
                app_build=p["appBuild"],
                app_version=p["appVersion"],
                phone_model=p["phoneModel"],
                phone_os=p["phoneOS"],
                home=p.get("home"),
                address=p.get("address"),
                access_door_map=access_door_map,
                master=p["master"],
            )

            pairings.append(pairing)

        return pairings

    async def pairings(self) -> List[Pairing]:
        async with self._create_http_client() as client:
            response = await client.get(
                f"{self.BASE_URL}/pairing/api/v3/pairings/me",
                headers=self._get_json_headers(),
            )

        if response.is_success:
            return self._parse_pairings(response)

        else:
            self._handle_error_response(response)

    async def directed_opendoor(self, device_id: str, access_id: AccessId) -> str:
        data = json.dumps(access_id.__dict__)

        async with self._create_http_client() as client:
            response = await client.post(
                f"{self.BASE_URL}/deviceaction/api/v1/device/{device_id}/directed-opendoor",
                headers=self._get_json_headers(),
                data=data,
            )

        if response.is_success:
            return response.text

        else:
            self._handle_error_response(response)

    async def f1(self, device_id: str) -> str:
        data = json.dumps({"deviceID": device_id})

        async with self._create_http_client() as client:
            response = await client.post(
                f"{self.BASE_URL}/deviceaction/api/v1/device/{device_id}/f1",
                headers=self._get_json_headers(),
                data=data,
            )

        if response.is_success:
            return response.text

        else:
            self._handle_error_response(response)

    async def get_user_info(self) -> User:
        async with self._create_http_client() as client:
            response = await client.get(
                f"{self.BASE_URL}/user/api/v1/users/me",
                headers=self._get_json_headers(),
            )

        if response.is_success:
            parsed_json = response.json()

            return User(
                email=parsed_json["email"],
                locale=parsed_json["locale"],
                accept_sharing=parsed_json["acceptSharing"],
                accept_privacy=parsed_json["acceptPrivacy"],
                enabled=parsed_json["enabled"],
                created_at=datetime.datetime.fromisoformat(parsed_json["createdAt"]),
                country=parsed_json["country"],
                city=parsed_json["city"],
                area=parsed_json["area"],
                zone=parsed_json["zone"],
                subzone=parsed_json["subzone"],
                pin=parsed_json.get("pin"),
                pin_date=parsed_json.get("pinDate"),
                unique_session=parsed_json["uniqueSession"],
                provider=parsed_json.get("provider"),
                name=parsed_json.get("name"),
            )

        else:
            self._handle_error_response(response)

    async def get_device_info(self, device_id: str) -> DeviceInfo:
        async with self._create_http_client() as client:
            response = await client.get(
                f"{self.BASE_URL}/deviceaction/api/v1/device/{device_id}",
                headers=self._get_json_headers(),
            )

        if response.is_success:
            parsed_json = response.json()

            return DeviceInfo(
                device_id=parsed_json["deviceId"],
                connection_state=parsed_json["connectionState"],
                status=parsed_json["status"],
                installation_id=parsed_json["installationId"],
                family=parsed_json["family"],
                type=parsed_json["type"],
                subtype=parsed_json["subtype"],
                num_block=parsed_json["numBlock"],
                num_subblock=parsed_json["numSubblock"],
                unit_number=parsed_json["unitNumber"],
                connectable=parsed_json["connectable"],
                iccid=parsed_json["iccid"],
                divert_service=parsed_json["divertService"],
                photocaller=parsed_json["photocaller"],
                wireless_signal=parsed_json["wirelessSignal"],
                blue_stream=parsed_json["blueStream"],
                phone=parsed_json["phone"],
                monitor=parsed_json["monitor"],
                monitor_or_guard_unit=parsed_json["monitorOrGuardUnit"],
                terminal=parsed_json["terminal"],
                panel_or_edibox=parsed_json["panelOrEdibox"],
                panel=parsed_json["panel"],
                streaming_mode=parsed_json["streamingMode"],
            )

        else:
            self._handle_error_response(response)


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
        help="Optional deviceId to avoid extra fetching (requires defining one or multiple accessId when opening doors)",
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
    parser.add_argument(
        "--f1",
        action="store_true",
        help="Calls F1 (optionally specifying deviceId)",
    )

    args = parser.parse_args()

    username = args.username
    password = args.password
    device_id = args.deviceId
    access_ids = args.accessId
    cache = args.cache
    reauth = args.reauth
    f1 = args.f1

    if (not f1) and ((device_id and not access_ids) or (access_ids and not device_id)):
        raise Exception(
            "Both deviceId and accessId must be provided when opening doors"
        )

    if access_ids:
        access_ids = [json.loads(access_id) for access_id in access_ids]

    client = BlueClient(cache)

    if client.needs_auth():
        await client.auth(username, password)

    elif client.needs_refresh():
        await client.refresh_token()

    if reauth:
        exit()

    if not device_id:
        LOGGER.info("Getting devices...")

        pairings = await client.pairings()
        if not pairings:
            raise Exception("No pairings found")

        pairing = pairings[0]
        device_id = pairing.device_id

    if f1:
        await client.f1(device_id)
        exit()

    provided_doors = device_id and access_ids

    if not provided_doors:
        access_ids = [
            d.access_id for d in pairing.access_door_map.values() if d.visible
        ]

        if len(pairings) > 1:
            LOGGER.info(
                f"Found multiple pairings, opening first one {pairing.tag} with deviceId "
                f"{pairing.device_id} ({len(access_ids)} doors), use --deviceId and --accessId "
                f"to specify which one to use."
            )
        else:
            LOGGER.info(
                f"Found {pairing.tag} with deviceId {pairing.device_id} ({len(access_ids)} "
                f"doors), calling directed opendoor for the first one..."
            )

    else:
        LOGGER.info(
            f"Success, using provided deviceId {device_id}, calling directed opendoor..."
        )

    # If user provided doors we open them all
    if provided_doors:
        for access_id_json in access_ids:
            access_id = AccessId(
                block=access_id_json["block"],
                subblock=access_id_json["subblock"],
                number=access_id_json["number"],
            )
            result = await client.directed_opendoor(device_id, access_id)
            LOGGER.info(f"Result: {result}")

    # Otherwise we just open the first one (ZERO?)
    else:
        result = await client.directed_opendoor(device_id, access_ids[0])
        LOGGER.info(f"Result: {result}")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main())
