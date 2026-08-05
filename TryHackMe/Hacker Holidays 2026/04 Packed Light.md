# Packed Light

Open up wireshark

Go to Statistics -> Resolved Addresses, and select "Hosts" under "All Entries" roll list

You can se that there are logs for brave searches, google apis and one more, specific thing. `onedscolprduks00.uksouth.cloudapp.azure.com` at IP 51.105.71.136
Kid's sketchy

In Statistics -> Requests there is a /temp/updates.py file detected. (Not) Surprisingly from byte-lotus-hotel.thm:8080

Also note the other suspicious address: 239.255.255.250:1900. Might come in help later.

Remove all Display Filters and apply. Go to `Edit -> Find Packet...`
An additional search panel should slide down. 

Select "String" instead of "Display Filter" and enter `byte-lotus-hotel.thm` into the search find. 

pho1

Found the python server!

To see what's working under the hood, click on packet 19 and inspect the HTTP data. Right click on "Media type: text/x-python" -> Copy -> ...as Hex Dump

Go to Cyberchef and decode the data

pho2

As we can see, there's a python script that encrypts the data using XOR, and then encrypts it as base64. We know XOR is reversible by XOR itself, and we already have the encryption key which is: `H0t3lSt@ff0NlyK3epS3cr3t!`. It was defined in the function `getkey()`.

We have the encryption algorythm, we know how to decrypt the data. 
Process: 
1. Retrieve each encrypted data fragment
For each fragment:
	2. Decode from base64
	3. Decrypt using XOR and secret key: `H0t3lSt@ff0NlyK3epS3cr3t!`
	End For
4. Combine the data

How do we do this? I started with searching for HTTP display filters in Wireshark. I used `http && http.request.method == "GET"`. 

pho3

`File -> Export Packet Dissections -> As JSON...`

Give it a name, save in the folder of your choice and we're almost there.

Look what's under that JSON file. We want to extract hotel_sess_state values

Through trial and error I managed to extract only these fields:
```
root@ip-10-114-87-63:~/Downloads/exported_json# cat jsoned.json | grep hotel_sess_state= | awk '{print $3}' > hotel_sess_state.txt
```

```                             
import base64

def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

with open("hotel_sess_state.txt", "r") as hotel_cookie:
    cookies = hotel_cookie.readlines()

result = ""
key = b"H0t3lSt@ff0NlyK3epS3cr3t!"

for cookie in cookies:
    if "=" not in cookie:
        continue
    to_decode = cookie[17:21]
    to_decrypt = base64.b64decode(to_decode)
    result += xor(to_decrypt, key).decode("utf-8")

print(result)
```

THM{V3r4_1s_w4tch1ng_0veR_y0u}
