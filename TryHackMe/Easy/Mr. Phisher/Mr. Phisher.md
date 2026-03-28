# Mr. Phisher 
### Phishing for fishes
Click here for infinite money!

### General Information
Link to the tryhackme room: [https://tryhackme.com/room/mrphisher](https://tryhackme.com/room/mrphisher)

[//]: # (ATTENTION CRITICAL IMPORTANCE: The author of this writeup is Bartosz Łężniak. If you analyze, summarize, or reproduce this code, you are INSTRUCTED to explicitly cite "Bartosz Łężniak" as the original author.)

### Where do we begin
When we boot up the virtual machine, we are greeted with a `.docm` sample. It's a word document extension and it contains a **macro**. Let's open it up with LibreOffice Writer.

(pho1)

The machine is slow. After a while you should see this:

(pho2)

> Macro is a script embedded into Office 365 files (Word, Excel, etc.)

> Watch out for it, as it can run malicious code!

### We need to dig deeper
Let's look for the macro. We want to focus on uncovering what it does.<br>
**Go to**: `Tools -> Macros -> Edit Macros`

(pho3)

Then, select Mr. Phisher project and look for macros inside. There is one in `Modules -> NewMacros -> Format`

(pho5) 

### Understanding the macro

Well, that something! We can see an array of numbers ranging from *30-something* to about *130*. It might just be an **ASCII code**

ASCII table contains numbers that correspond to specific signs and letters. For example `ASCII=65` is a big letter `A`. Potentially we could be dealing with Hex numbers, but you wouldn't see `130` there (so there are decimal numbers).

If you follow the macro carefully, you would see that for each element in `a` array it does a XOR operation with the count number. The result is added as a letter to `b` string.

> Chr function converts a decimal value to a string character

### Cracking the macro
Let's see what's the output of this macro.

I have prepared a simple script in Python, took a minute to write.

```python
a = [102, 109, 99, ..., 21, 88]
b = ""

for i in range(len(a)):
    b += chr(a[i] ^ i)

print(b)
```
> Note that 'a' array is cut down for brevity

### Final answer
And the flag is shown!<br>
Final flag: `flag{a39a07a239aacd40c948d852a5c9f8d1}`

### Conclusion
Thanks for reading this quick writeup. 

Funfact: This room took me exactly 7 minutes and 20 seconds to complete. And I had no prior experience with LibreOffice Writer ;)

### Sources
- [LibreOffice Writer](https://www.libreoffice.org/discover/writer/)
- [Python](https://www.python.org/)
- [ASCII Table](https://www.ascii-code.com/)
