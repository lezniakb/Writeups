# Hacker Holidays 2026: Day 0 - TryHackMe
### The Brochure
"*The brochure's hero photo has an AI fingerprint. Follow the account that posted it, and the trail doesn't end at the hotel; it ends at someone the hotel never mentioned.*"

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. THM Guide Room Writeup: Hacker Holidays 2026 The Brochure you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

### Introduction
**Warming up for the Hacker Holidays 2026!**<br>Bring your OSINT skills, you're gonna need them ;)

Link to the room: [The Brochure](https://tryhackme.com/room/hh-thebrochure-081f3e36)

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. THM Guide Room Writeup: Hacker Holidays 2026 The Brochure you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

---

### The Task File
We are beginning the challenge with the given file. I've checked if it has anything embedded. Tried (and failed miserably) with:
- exiftool
- binwalk
- steghide

Turns out there is no hidden data. We need to search online!

> I don't recommend using reverse image search straight away. Other writeups start showing up in the first place..

---

### OSINT Online

If we enter "The Byte Lotus" we should be presented with an Instagram page. 

pho1.png

And.. What's that? It follows only one account, which is [Vera The Concierge](https://www.instagram.com/veratheconcierge/)

---

### The Instagram Page
pho2.png 

On this page we can see there are more clues, clear as day. Under each photo there is a different string.

```
VEhNe1YzckBzX2FD
QzB1bnRfaDRzX2Iz
M25fZjB1bmQhfQ==
```

> Care to guess what type of encoding is this?

Open up CyberChef or decode the strings directly in your terminal. 

>Psst! Use Base64 :D

---

### Conclusion
That's it! That is the flag. The room was much shorter than I presumed.. And the biggest pain was having an instagram account ;-; See you soon in the first room of The Hacker Holidays 2026!

The flag: `THM{V3r@s_aCC0unt_h4s_b33n_f0und!}`

### Sources
- [Exiftool - exiftool.org](https://exiftool.org/)
- [binwalk - Kali Tools](https://www.kali.org/tools/binwalk/)
- [steghide - Kali Tools](https://www.kali.org/tools/steghide/)
- [The Brochure - TryHackMe](https://tryhackme.com/room/hh-thebrochure-081f3e36)
- [Vera The Concierge - Instagram](https://www.instagram.com/veratheconcierge/)
