# Fermax Blue Intercom Script

## Usage

1. Clone the repository and navigate to the root directory.
2. Install the httpx module by running `pip install httpx`.
3. Run the script with the required arguments: `python3 open_door.py --username <USERNAME> --password <PASSWORD>`.
4. If you want to avoid extra fetching, you can also provide the optional `--deviceId` and `--accessId` arguments.
5. The script will output a message indicating whether the door was successfully opened or not.

## Arguments

-   `--username`: Required. Fermax Blue account username.
-   `--password`: Required. Fermax Blue account password.
-   `--deviceId`: Optional. Device ID to avoid extra fetching (requires accessId when opening doors).
-   `--accessId`: Optional. Access ID(s) to avoid extra fetching (use with deviceId).
-   `--no-cache`: Optional. Disables auth token cache usage (read/write).
-   `--reauth`: Optional. Use it to just force reauth, when using this option no door will be open, just use it to refresh the token, check your credentials...
-   `--f1`: Optional. Calls the F1 function, optionally specify deviceId.

## Examples

### Home Assistant

You can use this script with Home Assistant using the `shell_command` integration.

Save it in a directory under `config`, something like `your_home_assistant_dir/config/python_scripts/open_door.py`, then add the following to your `configuration.yaml`:

*NOTE: Check how it is used in the examples below.*

```
shell_command:
  open_door: 'python3 python_scripts/open_door.py --username USERNAME --password PASSWORD ...'
```

### Opening first door (maybe ZERO?)

```bash
open_door.py --username email@domain.com --password yourpassword
```

### Opening first door and disabling auth token cache

```bash
open_door.py --username email@domain.com --password yourpassword --no-cache
```

### Opening the provided door

```bash
open_door.py --username email@domain.com --password yourpassword --deviceId 12345 --accessId '{"subblock": 0, "block": 0, "number": 0}'
```

### Opening multiple doors

```bash
open_door.py --username email@domain.com --password yourpassword --deviceId 12345 --accessId '{"subblock": 0, "block": 0, "number": 0}' '{"subblock": 1, "block": 1, "number": 1}'
```

### Force authentication

```bash
open_door.py --username email@domain.com --password yourpassword --reauth
```

### F1 *(not properly tested)*

```bash
open_door.py --username email@domain.com --password yourpassword --f1
```

```bash
open_door.py --username email@domain.com --password yourpassword --f1 --deviceId 12345
```

## How it works

The script sends an HTTP request to the Fermax Blue Servers to authenticate the user and obtain an access token. The access token is cached into a JSON file (in the script directory) to avoid unnecessary API calls in the future.

The script then sends another HTTP request to the Fermax Blue Servers to obtain the device ID and access ID, which are required to open the door.

Finally, the script sends a third HTTP request to the Fermax Blue API to open the door.

## Disclaimer

This script was tested on a Fermax 9449 using Python 3.9.
