# Corridor
### Can you escape the Corridor?
"I open the **door** in my corr**idor**"

---

### Intro
Link to the TryHackMe room: [Corridor](https://tryhackme.com/room/corridor)

We don't even need scanning the target machine here. Nmap is going to rest for a little while ;)

Target machine IP and Attackbox IP also isn't needed for this writeup. You'll see why in a while. 

---

### Which door to open

First we are presented with a room with 13 doors. If you click each one you'll find out there is nothing there. 

> What to dooo, what to do?

As the name suggests, it's related to IDOR vulnerability

> get it, 'Corr**IDOR**'? ;) 

By now we should already know that there is no difference between each room. The photo is the same, the HTML code is the same.. There is nothing to exploit there. 

**BUT**. Look at the URL in each room. Pretty long and random, right? Looks like a *hash*. 

(pho1)

[Hash identifier](https://hashes.com/en/tools/hash_identifier) shows us it's probably an MD5 hash. As we know, it's pretty easy to "revert" it using rainbow tables.

> We cannot actually revert one-way hash, but if we provide a table of strings along with their result, we can see which hash is the one that we are interested in 

Look for a site that will "decode" MD5 hash for you. [Crackstation](https://crackstation.net) is a great tool for that. You can paste each URL (there are 13 of them) line by line, and you'll get your result. 

(pho2)

> Turns out, the rooms are simply numbered starting from `1`.

We know it's an IDOR vulnerability. What if we use URL that is an MD5 hash of the number `0`? Or try other numbers?

Let's create an MD5 hash:<br>
`0` sign equals: `cfcd208495d565ef66e7dff9f98764da` in MD5.

And now use it as the URL subpage. 

(pho3)

There we go! A flag is right there!

Final flag: `flag{2477ef02448ad9156661ac40a6b8862e}`

---

### Conclusion
This was a 5-minut solution for a simple IDOR vulnerability. The objective was to identify that each door opened a subsite that was under an MD5 hash in URL. The last thing to do was to generate an MD5 hash for `0` sign and use it as URL.

---

### Sources
- [Hash Type Identifier](https://hashes.com/en/tools/hash_identifier)
- [CrackStation](https://crackstation.net/)
- [MD5 Encoder](https://elmah.io/tools/md5-encoder/)
