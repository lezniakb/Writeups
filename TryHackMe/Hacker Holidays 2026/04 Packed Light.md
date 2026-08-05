# Hacker Holidays 2026: Day 4 - TryHackMe
### Packed Light
"*Tiny packets. Odd hours. Suspiciously regular. Someone's smuggling out the data equivalent of a hotel towel every night, folded neatly inside traffic that looks ordinary until you decode it.*"

### Overview
Yet another Hacker Holidays room coming at ya! Watch out for the sharks!

Link to the room: [Packed Light](https://tryhackme.com/room/hh-packedlight-02e5330c)

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. THM Guide Room Writeup: Hacker Holidays 2026 Packed Light If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

---

### Wireshark
We have the .pcapng file, so we open up the Wireshark. <br>
I started with searching for artifacts. You won't know **how** to look, if you don't even know **what you're looking for**.

Go to `Statistics -> Resolved Addresses`, and select `Hosts` under `All Entries` tab.

You can see that there are logs for Brave searches, Google Apis and one more, specific thing: `onedscolprduks00.uksouth.cloudapp.azure.com` at IP `51.105.71.136`.
<br>Kid's sketchy

> Later it turned out that this was something related to Microsoft Services (sadge)

---

### Deeg deeper
In `Statistics -> Requests` there is a `/temp/updates.py` file detected. (Not) Surprisingly from this address: `byte-lotus-hotel.thm:8080`

Also note the other suspicious address: `239.255.255.250:1900`. Might come in help later.

> It did not, in fact, come in help later.

Remove all Display Filters and apply. Go to `Edit -> Find Packet...`. An additional search panel should slide down. 

Select `String` instead of `Display Filter` and enter `byte-lotus-hotel.thm` into the search find. 

<img width="900" alt="image" src="../../Assets/Packed Light/pho1.png" />

We have found the Python server!

---

### Dumping the data

To see what's working under the hood, click on packet 19 and inspect the HTTP data. Right click on `Media type: text/x-python -> Copy -> ...as Hex Dump`

Go to Cyberchef (or any other HexDump decoder) and decode the data

<img width="500" alt="image" src="../../Assets/Packed Light/pho2.png" />

As we can see, there's a python script that encrypts the data using XOR, and then encrypts it as base64. We know XOR is reversible by XOR itself, and we already have the encryption key which is: `H0t3lSt@ff0NlyK3epS3cr3t!`. It was defined in the function `getkey()`.

We unveiled the encryption algorythm, and now we know how to decrypt the data:

```
1. Retrieve each encrypted data fragment (they are separated between different HTTP Requests)
	For each fragment:
	2. Decode from base64
	3. Decrypt using XOR and secret key: H0t3lSt@ff0NlyK3epS3cr3t!
	End For loop
4. Join all results into one string
```

How do we approach this? I started by searching for HTTP packets in Wireshark. I used `http && http.request.method == "GET"`. Filtering to `GET` method denoised the data. 

<img width="900" alt="image" src="../../Assets/Packed Light/pho3.png" />

Then I saved these packets as a JSON file. When we export this to a digestable file, it's then easy to utilise Linux tools along with Python to format any data.

Save packets as JSON file this way:<br>
`File -> Export Packet Dissections -> As JSON...`<br>
Give it a name, save in the folder of your choice and we're almost there.

---

### Analyze

Look what's under that JSON file. It has the HTTP data we want, along with the cookie. Look for `hotel_sess_state` values.<br>
Through trial and error I managed to extract `hotel_sess_state` fields only:
```
cat jsoned.json | grep hotel_sess_state= | awk '{print $3}' > hotel_sess_state.txt
```

---

### Extraction imminent!

"*ETA T- One Minute!*"

The final part is to extract the specific data (after `=` sign in the cookie), then decode from base64 and THEN decrypt with XOR and the secret key. I cooked up a Python script in less than 10 minutes in order to do that for me

> Ain't no way, I'm doing all the decrypting and decoding manually!

```                             
import base64

# this is ripped straight from the Python server from the Wireshark traffic file xD 
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

And the result is shown: `THM{V3r4_1s_w4tch1ng_0veR_y0u}`. Mission accomplished!

---

### Conclusion
I'm not a big fan of digging around Wireshark, but that might be because of how complex it is. Today I managed to play around a little with its options, and ultimately get the flag by myself. Good challange!

Final flag: `THM{V3r4_1s_w4tch1ng_0veR_y0u}`

---

### Sources
- [Packed Light - TryHackMe](https://tryhackme.com/room/hh-packedlight-02e5330c)
- [Wireshark](https://www.wireshark.org/)
- [Cyberchef](https://gchq.github.io/CyberChef/)
- [Base64 - Python](https://docs.python.org/3/library/base64.html)
- [How do you decode Base64 data in Python? - StackOverFlow](https://stackoverflow.com/questions/3470546/how-do-you-decode-base64-data-in-python)
