# TBU

OhSINT 
https://tryhackme.com/room/ohsint

### Welcome to the challenge

We are on the AttackBox and the Task File is at `/root/Rooms/OhSINT`

### 1. What is this user's avatar of?

use exiftool

`exiftool WindowsXP.jpg`

We can clearly see the copyright is credited to `OWoodflint`

So we have his username - let's look for the avatar

If we enter his username to a search engine of your choice, we should see this X profile:
```
https://x.com/OWoodflint
```

(pho1)

It's clearly a cat. So the answer is:

Answer 1: `cat`

### 2. What city is this person in?

Bssid: B4:5D:50:AA:86:41 - Go nuts!

https://github.com/GONZOsint/geowifi

For this, we need to lookup the BSSID

Wigle.net is a great place to do that (but you need an account)

If we go into View -> Advanced Search there's a BSSID/MAC field there. Query this BSSID and see the result!

(pho2)

We've found etimated latitude and longitude.
In Google Maps, it opens up in London. (Next to 7 Chales II street)

Answer 2: `London`

### 3. What is the SSID of the WAP he connected to?
Easy. As we've already identified the router, SSID is already visible on Wigle.net - plain as day

Answer 3: UnileverWiFi

### 4. What is his personal email address?

When digging around Startpage, I've found two other sites related to Oliver Woodflint (OWoodflint):
- [Oliver Woodflint Blog](https://oliverwoodflint.wordpress.com/)
- [OWoodfl1nt Github](https://github.com/OWoodfl1nt/people_finder)

He has a repository called `people_finder`
Well, let's look for him, shall we?

In the README.md he gave us his own email account: `OWoodflint@gmail.com`. And yes! That's the answer.

(pho3)

Answer 4: `OWoodflint@gmail.com`

### 5. What site did you find his email address on?

Answer 5: `Github`

### 6. Where has he gone on holiday?

He told us where he has gone on holiday right in the only post on his [Wordpress](https://oliverwoodflint.wordpress.com/) site.

(pho4)

Hey, I'm walking here!

Answer 7: `New York`

### 7. What is the person's password?

I stopped for a second to think where it could be. Wordpress and Github were combed by me (I even saw cringe Github issues for this repo). Github is being funny at the time of writing this, and throws 5xx HTTP Errors at me..

5 minuts lated.. I swear, what is going on with Github today?

(pho5)

Turns out the password wasn't on Github. It's actually in Wordpress site source code. If you open the source code of `https://oliverwoodflint.wordpress.com/author/owoodflint/` you'll eventually notice line 219:
```
<p style="color:#ffffff;" class="has-text-color wp-block-paragraph">pennYDr0pper.!</p>
```

Turns out that is the password!

Answer 7: `pennYDr0pper.!`

### Conclusion

### Sources
- X (link)
- WiGLE (link)
- Github (link)
- Wordpress (link)
