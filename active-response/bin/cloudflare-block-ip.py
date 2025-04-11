#!/usr/bin/env python3
import datetime
import sys, json, requests
from pathlib import PureWindowsPath, PurePosixPath

# ————————————————————————————————————————————— WORKS!!!!
CLOUDFLARE_API_TOKEN = "CLOUDFLARE_API_TOKEN"
ACCOUNT_ID           = "ACCOUNT_ID"
LIST_ID              = "LIST_ID"
BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rules/lists/{LIST_ID}/items"
LOG_FILE = "/var/ossec/logs/active-responses.log"
#LOG_FILE = "/tmp/active-responses.log"

HEADERS = {
    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
    "Content-Type": "application/json",
}

def usage():
    print(f"Usage: {sys.argv[0]} [add|delete] <IP>")
    sys.exit(1)

def cf_request(method, url, payload=None, expect_status=(200,201,204)):
    resp = requests.request(method, url, headers=HEADERS, json=payload)
    data = resp.json()
    if resp.status_code not in expect_status or not data.get("success", True):
        print(f"❌ Error ({resp.status_code}): {json.dumps(data, indent=2)}")
        sys.exit(1)
    return data

def get_item_id(ip):
    data = cf_request("GET", BASE_URL)
    for item in data["result"]:
        if item.get("ip") == ip:
            return item["id"]
    return None

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg +"\n")


def setup_and_check_message(argv):

    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return message


def send_keys_and_check_message(argv, keys):

    # build and send message with keys
    keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})

    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    # read the response of previous message
    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return message
   
    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret


def main(argv):

    write_debug_file(argv[0], "Started")

    # validate json and get command
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:

        """ Start Custom Key
        At this point, it is necessary to select the keys from the alert and add them into the keys array.
        """

        alert = msg.alert["parameters"]["alert"]
        keys = [alert["data"]["srcip"]]
        ruleid = [alert["rule"]["id"]]
        ruledescription = [alert["rule"]["description"]]

        """ End Custom Key """

        """ Start Custom Action Add """

        payload =  [
            {
                "ip": keys[0],
                "comment": f"Blocked by Wazuh ({datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}). Rule Id:{ruleid[0]}. Rule Description:{ruledescription[0]}"
            }
        ]
        cf_request("POST", BASE_URL, payload, expect_status=(200,201))
        print(f" IP {keys[0]} added.")

        """ End Custom Action Add """

    elif msg.command == DELETE_COMMAND:

        """ Start Custom Action Delete """

        item_id = get_item_id(keys[0])
        if not item_id:
            print(f" IP {str(keys)} doens't found.")
            sys.exit(1)
        payload = {"items": [{"id": item_id}]}
        cf_request("DELETE", BASE_URL, payload, expect_status=(200,201))
        print(f" IP {str(keys)} removed.")

        """ End Custom Action Delete """

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")

    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)