# Fools Mate
### Can you bypass the engine?

"*All I have to do is hit a button.*"

### Overview
It's a quick, 15-min room. All you have to do is figure out how to evade the malicious engine. He just **won't** let us win!

Attackbox IP: 10.114.76.55<br>
Target Machine IP: 10.114.152.106

---

### Look around
Obviously I started with enumerating the machine. But Nmap and Gobuster yielded nothing of value. Fear not! The room is not about pwning the machine - just executing a checkmate on the opponent.

--- 

### Checkmate?
You don't have to be a genius to see how you can checkmate your opponent in one move. But...

pho1

Holey Canoley! Cheater, Cheater! He just **WON'T** let us win!

---

### Solutions

Two things came to my mind. First, intercepting the request and forcing my move through HTTP Requests. If you open up Burp Suite, and try to intercept a request, it becomes clear that the popup is executed locally, even before creating the HTTP Request. We can't intercept that. But we WILL come back to that later.

So with this, I thought I should dig up JavaScript that is saved locally. Maybe I'm able to modify the JS code and send the request eventually. 

The JS code was saved and analyzed for the alert as well as for the API endpoints. 

pho2

Here I stood with these two choices. Create a direct request to API and see if that works, or play around with JS. 

I went with the first choice, and returned to Burp Suite. Turns out you can make other moves on the checkboard, just not the one with which you win. First, I reset the board (and forwarded the request through Burp), then I selected A1 and moved it to A2. Burp intercepted this move. I sent it to `Repeater` in order to play with it. The only thing that had to be changed was the target in HTTP Request body.

pho3

`"to":"a2"` was changed to `"to":"a8"`

And that was all there was to it. The flag was included in the Response.

---

### Funfact
You can proceed to play chess without using the obvious move. You can win this and get the flag anyway. But because the flag is returned in a JSON response, you won't see it in GUI. So JavaScript manipulation wouldn't really work well this way. 

---

### Conclusion
A quick and fun room that developed my thinking skills. I had to ask myself how I can evade the JavaScript. It was satisfying! Thanks for coming by and reading yet another writeup :)

---

### Sources
- [Burp Suite](https://portswigger.net/burp/communitydownload)
- [Burp Suite Repeater Guide](https://portswigger.net/burp/documentation/desktop/tools/repeater)
