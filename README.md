## Fermax Blue Intercom Script

# Usage

1. Clone the repository and navigate to the root directory.
2. Install the requests module by running pip install requests.
3. Run the script with the required arguments: python3 open_door.py --username <USERNAME> --password <PASSWORD>.
4. If you want to avoid extra fetching, you can also provide the optional --deviceId and --accessId arguments.
5. The script will output a message indicating whether the door was successfully opened or not.

# Arguments

-   `--username`: Required. Fermax Blue account username.
-   `--password`: Required. Fermax Blue account password.
-   `--deviceId`: Optional. Device ID to avoid extra fetching (requires accessId).
-   `--accessId`: Optional. Access ID to avoid extra fetching (use with deviceId).
-   `--cache`: Optional. Set to False if you don't want to use the cache to save the auth token (enabled by default).

# How it works

The script sends an HTTP request to the Fermax Blue Servers to authenticate the user and obtain an access token. The access token is cached into a JSON file (in the script directory) to avoid unnecessary API calls in the future.

The script then sends another HTTP request to the Fermax Blue Servers to obtain the device ID and access ID, which are required to open the door.

Finally, the script sends a third HTTP request to the Fermax Blue API to open the door.

# Disclaimer

This script was tested on a Fermax 9449.
