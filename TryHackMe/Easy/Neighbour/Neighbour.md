# Neighbour

"Hi-diddly-ho Neighbourino!"

### General information
Link to the tryhackme room: [Neighbour](https://tryhackme.com/room/neighbour)

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

**Attacker IP**: 10.114.87.219<br>
**Target IP**: 10.114.157.65

### The webpage

Boot up your browser and go to `http://[Target_IP]/`.<br>I scanned the machiner with Nmap in the background. There is only port 22 (ssh) and 80 (http).

At the site, we're immediately met with a login screen. 

> But we don't have credentials! 

Oh, there's a note to use `Ctrl+U` in order to log in with guest credentials. `Ctrl+U` opens up HTML source code of this login page.<br>On `line 34` there is a comment with guest credentials.

<img width="1000" height="191" alt="pho1" src="https://github.com/user-attachments/assets/4dcd48a6-d16e-4f3d-b4b5-10e1ab64143f" />

login: `guest`<br>
password: `guest`

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

Logged in. They tell us not to peek inside other users' profiles.. But we are pentesters! We **can't** resist the urge!

<img width="1000" height="312" alt="pho2" src="https://github.com/user-attachments/assets/7a02b204-64cb-4f54-a21f-89f80897089c" />

Look at URL. You can see there's a query string `user=guest`.

> Query strings are variables used by backend application. They are delimited by `?` sign in the URL

What if we change `guest` to `admin`? 

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

<img width="1000" height="334" alt="pho3" src="https://github.com/user-attachments/assets/86641c27-0f0b-4905-9bff-dad57e0d774c" />

We accessed admin panel. We got the flag. *Classic IDOR vulnerability*.

> IDOR means Insecure Direct Object Reference and is related to broken access control

Final flag: `flag{66be95c478473d91a5358f2440c7af1f}`

It's no surprise since the author of this CTF told us `IDOR room` is "*similar content*"...

### Conclusion
That was a 5-minute room picturing an IDOR vulnerability. A quick reminder why query strings (and user input overall) should always be validated. We have accessed admin panel to which we had no credentials. 

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

### Sources
- [Query string](https://en.wikipedia.org/wiki/Query_string)
- [IDOR (Portswigger)](https://portswigger.net/web-security/access-control/idor)
