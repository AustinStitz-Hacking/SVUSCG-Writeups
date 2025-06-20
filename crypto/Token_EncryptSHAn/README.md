# Token EncryptSHAn (392)

## Description

I've vibe-coded a note taking service using the most secure token encryption scheme possible. Can you read the notes of the `admin`?

## Files

* [token_encryptSHAn.py](token_encryptSHAn.py)

## Writeup

This challenge gives us a Python script that contains the code for the server.

It's best to go ahead and review that since reviewing this will allow us to know what to exploit.

Going down line by line, a few things stand out.

First, there is a `sanitize_username` function that seems to only allow lowercase letters:

```python
def sanitize_username(username):
    """Removes any characters that are not lowercase English letters."""
    return bytes(filter(lambda x: 96 < x < 123, username))
```

We also see an `hmac` function that just provides the hexadecimal representation of an SHA256 hash of a key and a token:

```python
def hmac(token):
    return hashlib.sha256(key.encode() + token).digest()
```

Within the `get_current_username` function, we see this:

```python
    token_payload_str = decoded_token_str[:-HMAC_HEX_LENGTH]
    received_hmac_hex = decoded_token_str[-HMAC_HEX_LENGTH:]

    # Verify HMAC
    expected_hmac_bytes = hmac(token_payload_str)
    expected_hmac_hex = expected_hmac_bytes.hex()

    if not secrets.compare_digest(received_hmac_hex, expected_hmac_hex.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: HMAC verification failed.",
            headers={"WWW-Authenticate": "Bearer"},
        )
```

So clearly, the end of a token string is the hash of the beginning of the token string.

And when we log in, we can see how this token is generated:

```python
    # Generate token components
    nonce_bytes = secrets.token_hex(8).encode('utf-8')
    ts_bytes = str(int(datetime.now(timezone.utc).timestamp())).encode('utf-8')

    # Construct the main part of the token
    payload_part = b"nonce=" + nonce_bytes + b"&ts=" + ts_bytes + b"&user=" + sanitized_username
    token_data_part = b"len=" + str(len(payload_part)).encode('utf-8') + b"&" + payload_part

    # Calculate HMAC for the token data part
    calculated_hmac_hex_str = hmac(token_data_part).hex() # hmac returns bytes, .hex() returns str
    token_string_with_hmac = token_data_part + calculated_hmac_hex_str.encode('utf-8') # append hmac_hex as bytes

    # Base64 encode the token string
    # token_string_with_hmac is already bytes
    base64_encoded_token = base64.b64encode(token_string_with_hmac).decode('utf-8')
    # Return the token directly in the response body
    return {"token": base64_encoded_token}
```

Since we have to read the notes of the `admin` user, we need to find a way to forge the token of the user and then read the admin's notes. That basically means we need to find a way to determine a new hash of a new user given a new username.

Luckily for us, the sanitized username is at the end of the hashed data. And it is also important that it is sanitized as it is. SHA256 is vulnerable to hash length extension, meaning that given a known plaintext and its hash, such as our user's token and token hash, we can determine the new hash just with extra data added to the end of our plaintext token. 

Since this is such a well-known vulnerability in hashing algorithms, it was easy to find a solution on GitHub:
https://github.com/eid3t1c/Hash_Extender/tree/main

Now this is definitely probably not the best one out there, but it's the one I found. It is slightly broken in how it builds normally but since we want to include it in our own script, that's not really needed. It is a bit difficult as is to connect this to a script, but I basically pulled some of the important parts to the beginning of my Python script.

```python
from typing import List

def Default_State(): # Default State
    return [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def seperate(p): 
    final = []
    blocks = [p[x:x+64] for x in range(0,len(p),64)]
    for b in blocks:
        final.append([int.from_bytes(b[x:x+4],"big") for x in range(0,len(b),4)])
    
    return  final

# SHA-256 Functions
def Right_Shift(x,y):
    return x >> y

def Rotate_Right(x,y):
    return (x >> y) | (x << (32 - y)) & 0xffffffff

def sigma0(x):
    return Rotate_Right(x,7) ^ Rotate_Right(x,18) ^ Right_Shift(x,3)

def sigma1(x):
    return Rotate_Right(x,17) ^ Rotate_Right(x,19) ^ Right_Shift(x,10)

def Ch(x,y,z):
    return (x & y) ^ (~x & z)

def Maj(x,y,z):
    return (x & y) ^ (x & z) ^ (y & z)

def Sigma0(x):
    return Rotate_Right(x,2) ^ Rotate_Right(x,13) ^ Rotate_Right(x,22)

def Sigma1(x):
    return Rotate_Right(x,6) ^ Rotate_Right(x,11) ^ Rotate_Right(x,25)

# SHA-256 constant 64  32 bit words
K = bytearray.fromhex("428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5"
                      "d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174"
                      "e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da"
                      "983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca635114292967"
                      "27b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85"
                      "a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa070"
                      "19a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3"
                      "748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2")


K_blocks = [int.from_bytes(K[x:x+4],"big") for x in range(0,len(K),4)]


def sha256(message,state:List[int]):

    H = state
    
    padded_message = seperate(message) # W[:16]

    Total_Blocks = len(padded_message) # How many blocks

    for i in range(0,Total_Blocks):
        
        rounds = [padded_message[i][v] for v in range(0,16)]
        
        # Prepare the rounds
        for w in range(16,64): # W[16:64]
            rounds.append((sigma1(rounds[w-2]) + rounds[w-7] + sigma0(rounds[w-15]) + rounds[w-16]) & 0xffffffff)
        
        # Current state initialization
        a,b,c,d,e,f,g,h = H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]

        # Shuffling
        for t in range(64):
            T1 = (h + Sigma1(e) + Ch(e,f,g) + K_blocks[t] + rounds[t]) & 0xffffffff
            T2 = (Sigma0(a) + Maj(a,b,c)) & 0xffffffff
            h = g 
            g = f
            f = e
            e = (d + T1) & 0xffffffff
            d = c 
            c = b
            b = a
            a = (T1 + T2) & 0xffffffff

        # Final state of I-th block
        H[0] += a 
        H[1] += b 
        H[2] += c 
        H[3] += d 
        H[4] += e 
        H[5] += f 
        H[6] += g 
        H[7] += h 
        H = [h & 0xffffffff for h in H]
    
    # Return H0||H1||H2||H3||H4||H5||H6||H7
    return b"".join([f.to_bytes(4,"big") for f in H]).hex()

def Bendian_STATE(signature,digest_size,state_blocks):
    state = []
    if len(signature) != digest_size:
        raise ValueError(f"The input hash must be {digest_size} bytes long.")
    for i in range(0,len(signature),digest_size//state_blocks):
        temp = signature[i:i+digest_size//state_blocks]
        state.append(int(temp,16))
    return state


# Split the hash from Little-endian hash functions [MD4, MD5]
def Lendian_STATE(signature):
    if len(signature) != 32:
        raise ValueError("The input hash must be 32 bytes long.")
    # Split the hash into 4 equal parts
    parts = [signature[i:i + 8] for i in range(0, 32, 8)]
    # Convert each part to little-endian format
    little_endian_parts = []
    for part in parts:
        temp = ""
        little_endian = part[::-1] # Revert It
        for j in range(0,len(little_endian),2): # For every hex digit
            temp += little_endian[j+1] + little_endian[j] # Make it little endian
        little_endian_parts.append(temp) 
    A = int(little_endian_parts[0],16)
    B = int(little_endian_parts[1],16)
    C = int(little_endian_parts[2],16)
    D = int(little_endian_parts[3],16)
    return A,B,C,D

def New(known:bytes,append:bytes,key_length:int,block_size,message_size_bytes,endian):
    # Re-create the same padded message as the server
    current_message_after_padding = known + b"\x80" + b"\x00" * ((block_size - len(known) - key_length - 1 - message_size_bytes) % block_size) + ((key_length + len(known)) * 8).to_bytes(message_size_bytes,byteorder=endian)
    # Append the extra data
    new_message =  current_message_after_padding + append
    # Calculate the new bit-byte length
    total_prefix = (key_length + len(current_message_after_padding) + len(append)) * 8
    # Create the same padded message that the server will process with the given hash
    to_hash = append + b"\x80" + b"\x00" * ((block_size - len(append) - 1 - message_size_bytes) % block_size) + (total_prefix).to_bytes(message_size_bytes,byteorder=endian)
    
    return new_message,to_hash

def result(new_m,new_s):
    print(f"""
    \t+------------------------++------------------------+
    \t|                   New Message                    |
    \t+------------------------++------------------------+\n""")
    print("\t" + new_m)
    print(f"""\n\t+------------------------++------------------------+
    \t|                   New Signature                  |
    \t+------------------------++------------------------+
    \n\t{new_s}
    """)

def runExtend(Data, Append, Key_length, Signature):
    try:
        new_message,to_hash = New(Data,Append,Key_length,64,8,"big") # Create the new message.
        new_state = Bendian_STATE(Signature,64,8) # split the given hash into a proper state
        new_hash = sha256(to_hash,new_state) # Hash the new message with the given hash being the state
        return (new_message, new_hash)
    except ValueError as e:
        print(e)
        return (None, None)
```

For our hash length extension, we can honestly just extend a username of "adm" to "admin", so we can start writing our part of the script.

```python
from requests import get, post
import base64

# Get the length of a random SHA256 hash
HASH_LEN = len("96902f573a8e08faf500b72e368ebad9acda5f611274c7de4108b92d6ba40c81")

# The host of the challenge website
host = "https://octbfouj.web.ctf.uscybergames.com"

# Register with credentials adm:test
print(post(host + "/register", json={"username": "adm", "password": "test"}).text)

# Log in with those credentials
x = post(host + "/login", json={"username": "adm", "password": "test"}).json()
# Get our token
token = x['token']

# Set up the Authorization header with the token as a Bearer token
headers = {"Authorization": "Bearer " + str(token)}
print(str(token))

# Decode our original token data
original_data = base64.b64decode(token).decode()[:-HASH_LEN]
print(original_data)

# Get the original hash
original_hash = base64.b64decode(token).decode()[-HASH_LEN:]
print(original_hash)

# Test by getting our notes (should be empty)
print(get(host + "/notes", headers=headers).text)

# We don't know the key length, so try from 0 to 100
for i in range(100):
	# Generate our new message and hash by adding "in" to "adm" to forge the admin's token
    new_message, new_hash = runExtend(original_data.encode(), b"in", i, original_hash)
    # Add our hash to the end of our token
    new_token = new_message + str(new_hash).encode()
    # Base64 encode
    full_token= base64.b64encode(new_token).decode()
    
    # Set our new Bearer token
    headers = {"Authorization": "Bearer " + str(full_token)}
    
    # Try getting the admin's notes list
    res = get(host + "/notes", headers=headers).text
    print(res)
```

Eventually, we see this:

![Getting the admin notes list](../../images/Pasted%20image%2020250618180821.png)

So our note is called `flag`!

We can change that last part of our script to read
```python
    # Try getting the flag
    res = get(host + "/notes/flag", headers=headers).text
    print(res)
```

And running that, we get the flag!

![Getting the flag](../../images/Pasted%20image%2020250618180929.png)

And the flag is `SVUSCG{9a74ed7744cadb21f6d3053eca197523}`!
