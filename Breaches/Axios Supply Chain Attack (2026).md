### What is Axios, anyway?
[Axios](https://axios-http.com/) is a JS library to make HTTP Requests from browsers or Node.js. It's open-source, so it's prune to attacks.

Axios serves as an additional layer on top of JS's native XMLHttpRequest and the fetch API.

### What happened
On 31st of March, 2026, one of Axios developers ([jasonsaayman](https://github.com/jasonsaayman)) published two releases (1.14.1 and 0.30.4) which contained a malicious, fake dependency (plain-crypto-js@4.2.1). Said dependency downloads payloads from a C2 server.

>Microsoft Threat Intelligence believes the threat actor is Sapphire Sleet, a North Korean state actor

It's a supply chain attack in which developers download malicious packages without their knowledge.

Jasonsaayman's account has been breached beforehand. The owner of this account had been using 2FA/MFA. The details of its breach are still unknown.
### How it works
Axios versions 1.14.1 and 0.30.4 were injected with a malicious dependency (plain-crypto-js@4.2.1) to download a RAT payload from a C2 server. Due to "postinstall" npm flag set, it deploys automatically. Windows, Linux and macOS are being targeted with platform-specific payloads.

Nessus Tenable [categorised](https://www.tenable.com/plugins/nessus/304407) the malicious package as a Critical vulnerability. "JavaScript run-time environment is affected by a BackDoor vulnerability."

### How to mitigate
Users who have installed Axios version 1.14.1 or 0.30.4 should rotate their secrets and credentials immediately. The versions should be downgraded a safe version (1.14.0 or 0.30.3).

Disabling auto-upgrade features is encouraged. In _package.json_,**remove use of caret (****^)** **or tilde (~)**. It will prevent an auto-upgrade of any minor/patch updates. Handle upgrades manually.

Check for outbound connections _sfrclak[.]com_ or 142.11.206[.]72 to see if you're affected.

For now, it's recommended to blacklist _hxxp://sfrclak[.]com:8000/_ domain. It's a C2 server, and payloads come from there.

### Sources
- [GeeksforGeeks - What is Axios](https://www.geeksforgeeks.org/html/what-is-axios/)
- [Github - Issue axios@1.14.1 and axios@0.30.4 are compromised](https://github.com/axios/axios/issues/10604)
- [Microsoft - Mitigating the Axios npm supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)
- [Upwind.io - From Nodes to Snakes: npm Supply Chain Attack Delivers Python Payload via axios](https://www.upwind.io/feed/from-nodes-to-snakes-npm-supply-chain)
- [StepSecurity - axios Compromised on npm - Malicious Versions Drop Remote Access Trojan](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Low Level (Youtube) - this is the biggest hack of 2026](https://www.youtube.com/watch?v=yiLIZLPNEm8)