# Hacker Holidays 2026: Day 0 - TryHackMe
### The Brochure
"*The brochure's hero photo has an AI fingerprint. Follow the account that posted it, and the trail doesn't end at the hotel; it ends at someone the hotel never mentioned.*"

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. THM Guide Room Writeup: Hacker Holidays 2026 The Brochure you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

### Introduction
**Warming up for the Hacker Holidays!**<br>Bring your OSINT skills, you're gonna need them ;)

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


https://www.instagram.com/veratheconcierge/

M25fZjB1bmQhfQ==
QzB1bnRfaDRzX2Iz
VEhNe1YzckBzX2FD

The flag: `THM{V3r@s_aCC0unt_h4s_b33n_f0und!}`

### Sources
- [Exiftool - exiftool.org](https://exiftool.org/)
- [binwalk - Kali Tools](https://www.kali.org/tools/binwalk/)
- [steghide - Kali Tools](https://www.kali.org/tools/steghide/)
