# RootMe
### Can you do it?
"Care for a root beer?"

### General Information
[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)
Link to the tryhackme room: [https://tryhackme.com/room/rrootme](https://tryhackme.com/room/rrootme)

Attack machine IP: 192.168.162.195<br>
Target machine IP: 10.113.170.216

### Reconnaissance
Let's ask ourselves a question: "What can we look for at the moment?"

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

We have Nmap to check what ports are open and what happens inside them!

```
└─$ nmap -sS 10.113.170.216 -p- -T4  
...
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
> Classic for a simple CTF. Only a HTTP website is up, along with ssh on port 22.

Question 1: `Scan the machine, how many ports are open?` <br>
**Answer 1**: `2`

Going futher, we should check what versions these services are.
```
└─$ nmap -sC -sV -O 10.113.170.216 -p22,80
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: HackIT - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
```
Question 2: `What version of Apache is running?` <br>
**Answer 2**: `2.4.41`

Question 3: `What service is running on port 22?` <br>
**Answer 3**: `ssh`

If we're feeling lucky, we could search for vulnerabilities on these specific versions.<br>
But at the moment, let's look for clues on HTTP website.

Let's enumerate main directory - maybe there are hidden subpages?
```python3
└─$ gobuster dir --url http://10.113.170.216/
    --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    -x html,php,txt
```
<img width="469" height="162" alt="1gobuster" src="https://github.com/user-attachments/assets/00fa7eac-ab11-4f02-8ff7-c6ad249d537c" />

After a minute or so, a secret '/panel' subpage is found!

> Notice '/uploads' folder, it will also prove useful to us! 

Question 4: `Find directories on the web server using the GoBuster tool.` <br>
**Answer 4**: `No answer needed`

Question 5: `What is the hidden directory?` <br>
**Answer 5**: `/panel/`

### Uploading webshell
We can upload a file there. This means we could try uploading .php webshell and exploit this page.<br>
I downloaded [PentestMonkey PHP Webshell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). 

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)
Remember to change IP and PORT variables to match the ones on your Attack Machine.

<img width="260" height="130" alt="2ip" src="https://github.com/user-attachments/assets/9ccb520d-76a1-4151-82ec-bc7b7211630d" />

We upload the file and...

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

<img width="300" height="350" alt="3upload" src="https://github.com/user-attachments/assets/fb50ef59-ba98-4c0b-9545-c751768671a3" />

PHP is not permitted :(<br>
Is there a workaround? Of course there is!

PHP comes with many [different extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst). You can try .php5 or similar and see what happens.<br>

<img width="300" height="350" alt="4upload" src="https://github.com/user-attachments/assets/b3f67280-93f9-4f13-a105-0a87faa9556d" />

> It's working, because website checks only for .php extensions. .php5 is different, so it gets a green light.

So we uploaded it. What now?<br>

### Execute, execute, execute!
We know there is /uploads folder. Navigate there.

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

<img width="575" height="304" alt="5uploads" src="https://github.com/user-attachments/assets/28fea976-0da2-43e7-893d-061de749e40c" />

On your Attack Machine, open netcat port in listening mode `nc -lvnp <PORT>` <br>
Select the same port number which you specified before in reverse shell .php file.

Now click the reverse shell in /uploads folder.<br>
The site should hang. This usually means it has connected to our open port on the Attack Machine.

<img width="692" height="254" alt="6revshell" src="https://github.com/user-attachments/assets/b382949c-0423-493a-9fd7-a0d889175b5a" />

>Success! We've established foothold access.

I also like to create an interactive session, so I used a python command:<br>
`python -c "import pty; pty.spawn('/bin/bash');"`

<img width="514" height="116" alt="7interactive" src="https://github.com/user-attachments/assets/1f2a7e59-5c86-4133-856f-dd746419f822" />

Look for the first flag.<br>
`find / -name "user.txt" 2>/dev/null`

In an instant we can see that the flag is in /var/www/user.txt<br>

Question 6: `Flag user.txt` <br>
**Answer 6**: `THM{y0u_g0t_a_sh3ll}`

### Escalate Your Privileges
Besides the flag, what's in `/var/www`?<br>
There's a bash history file. In CTFs authors sometimes forget about clearing their history, thus showing their way of preparing the challenge.

`cat /var/www/.bash_history`<br>
After opening the file, we can see the exact command to escalate our privileges

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

<img width="579" height="285" alt="8history" src="https://github.com/user-attachments/assets/febf436a-2208-4bed-9dec-1ce2fde496c7" />

If you want to do it yourself, search for SUID:
`find . -perm /4000 2>/dev/null` 

Python binary has SUID bit set! It means we can execute commands on behalf of the owner - which is root.

Question 7: `Search for files with SUID permission, which file is weird?` <br>
**Answer 7**: `/usr/bin/python`

GTFO Bins helps here. They can tell us what command should we use to exploit this vulnerability: <br>
`python -c 'import os; os.execl("/bin/sh", "sh", "-p")'`

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)
> Pssst.. That's the exact same command we saw in the history file ;)

After executing it, we finally become root

Question 8: `Find a form to escalate your privileges.` <br>
**Answer 8**: `No answer needed`

<img width="670" height="129" alt="9root" src="https://github.com/user-attachments/assets/0d563c79-3687-4a0b-bdc0-053187dfa991" />

Root flag is in /root directory, like in most cases.

Question 9: `Flag root.txt` <br>
**Answer 9**: `THM{pr1v1l3g3_3sc4l4t10n}`

### Conclusion
Thanks for reading! I took a break from creating writeups in Februrary, but we're back baby! 

### Sources
- [PentestMonkey PHP Webshell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
- [Other PHP file extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
- [GTFO Bins (Python)](https://gtfobins.org/gtfobins/python/)



