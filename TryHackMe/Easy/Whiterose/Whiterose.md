# Whiterose

**AttackBox IP**: 10.128.106.93<br>
**Target IP**: 10.128.160.220

`nmap -sS 10.128.160.220 -p- -vv -n -T4`

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

`nmap -sC -sV -O 10.128.160.220 -p22,80 -vv -n -T4`

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)

80/tcp open  http    syn-ack ttl 64 nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).

```

add to /etc/hosts:

```
10.128.160.220  cyprusbank.thm

```

Gobuster:

`gobuster dir --url 10.128.160.220 --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,log`

Dirsearch:

`dirsearch -u cyprusbank.thm`

> Nothing enumerated besides index.html

There is nothing in html code, no robots.txt, no easy access points

Let's try subdomain enumeration