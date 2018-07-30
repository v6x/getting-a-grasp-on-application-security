@title[Title]

Getting a grasp on

## Application security

---
@title[Table of contents]

### TOC

- Overview
- Practice

---
@title[Definition]

### What is the security?

> secure: from se- (“without”) +‎ cura (“care”);

> cura: From Proto-Indo-European *kʷeys- (“to heed”).

- https://en.wiktionary.org/wiki/security
- https://en.wiktionary.org/wiki/cura#Latin

> The condition of not being threatened, especially physically, psychologically, emotionally, or financially.

---

### What should be protected?

https://en.wikipedia.org/wiki/Computer_security#Vulnerabilities_and_attacks

- Financial systems
-	Utilities and industrial equipment
-	Government and Large corporations
-	Aviation and automobiles
-	Consumer devices, IoT and physical vulnerabilities
-	Energy sector, medical systems, ...

---

### Where should be protected?

https://en.wikipedia.org/wiki/Defense_in_depth_(computing)

![https://upload.wikimedia.org/wikipedia/commons/thumb/4/4c/Defense_In_Depth_-_Onion_Model.svg/500px-Defense_In_Depth_-_Onion_Model.svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/4/4c/Defense_In_Depth_-_Onion_Model.svg/500px-Defense_In_Depth_-_Onion_Model.svg.png)

---

### How do they attack?

https://en.wikipedia.org/wiki/Computer_security#Vulnerabilities_and_attacks

- Backdoor, Direct-access attacks, Privilege escalation
-	Denial-of-service attacks
-	Eavesdropping, Phishing
-	Spoofing, Tampering, Clickjacking, Social engineering
-	Multivector, polymorphic attacks

---

It seems to be very public.

### Common Vulnerabilities and Exposures

> The Common Vulnerabilities and Exposures (CVE) system provides a reference-method for publicly known information-security vulnerabilities and exposures.

- https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures
- https://cve.mitre.org/

---
@title[Internet security]

But, how about the internet world?

### Internet security

https://en.wikipedia.org/wiki/Internet_security

> Internet security is a branch of computer security specifically related to the Internet, often involving browser security[citation needed] but also network security on a more general level, as it applies to other applications or operating systems as a whole.

---

#### Threats

https://en.wikipedia.org/wiki/Internet_security#Threats

-	Malicious software
-	Denial-of-service attacks
-	Phishing
-	Application vulnerabilities

---

#### Remedies

https://en.wikipedia.org/wiki/Internet_security#Remedies

-	Network layer security
-	Internet Protocol Security (IPsec)
-	Multi-factor authentication
-	Security token
-	Electronic mail security
- Firewalls
- Browser choice

---
@title[Vulnerability]

### Vulnerability

https://en.wikipedia.org/wiki/Vulnerability_(computing)

> a vulnerability is a weakness which can be exploited by a Threat Actor, such as an attacker, to perform unauthorized actions within a computer system. To exploit a vulnerability, an attacker must have at least one applicable tool or technique that can connect to a system weakness.

---

Please, in software perspective.

- **Memory safety**: Buffer overflows and over-reads, Dangling pointers
- **Input validation errors**: Code injection, Cross-site scripting in web applications, Directory traversal, E-mail injection, Format string attacks, HTTP header injection, HTTP response splitting
- **Privilege-confusion bugs**: Clickjacking, Cross-site request forgery in web applications, FTP bounce attack, Privilege escalation
- **Race conditions**: Symlink races, Time-of-check-to-time-of-use bugs, SQL injection, Side-channel attack, Timing attack
- **User interface failures**: Blaming the Victim prompting a user to make a security decision without giving the user enough information to answer it, Race Conditions, Warning fatigue[34] or user conditioning.

---

Can we protect? How?

- As possible as before being attacked.
- As soon as possible after being attacked.

https://en.wikipedia.org/wiki/Security_bug

---
@title[Defend]

First, to defend in advance,
- study how they attack it,
- We study what we do wrong,
- And do not believe anything.

---

### Secure coding

https://en.wikipedia.org/wiki/Secure_coding

> Secure coding is the practice of developing computer software in a way that guards against the accidental introduction of security vulnerabilities. Defects, bugs and logic flaws are consistently the primary cause of commonly exploited software vulnerabilities.

Please see examples in wikipedia.

---

### Defensive programming

https://en.wikipedia.org/wiki/Defensive_programming

> Defensive programming is a form of defensive design intended to ensure the continuing function of a piece of software under unforeseen circumstances. Defensive programming practices are often used where high availability, safety or security is needed.

Also, please see examples in wikipedia, too.

---
@title[Cryptography]

### Cryptography

https://en.wikipedia.org/wiki/Cryptography#Modern_cryptography

Symmetric-key | Public-key
------------ | -------------
![https://upload.wikimedia.org/wikipedia/commons/2/27/Symmetric_key_encryption.svg](https://upload.wikimedia.org/wikipedia/commons/2/27/Symmetric_key_encryption.svg) | ![https://upload.wikimedia.org/wikipedia/commons/f/f9/Public_key_encryption.svg](https://upload.wikimedia.org/wikipedia/commons/f/f9/Public_key_encryption.svg)


---

### Cryptography protocol

https://en.wikipedia.org/wiki/Cryptographic_protocol

> A security protocol (cryptographic protocol or encryption protocol) is an abstract or concrete protocol that performs a security-related function and applies cryptographic methods, often as sequences of cryptographic primitives.


---

### Cryptographic primitive

https://en.wikipedia.org/wiki/Cryptographic_primitive#Commonly_used_primitives

- One-way hash function
- Authentication
- Symmetric key cryptography, Public key cryptography
- Digital signatures
- Mix network
- Private information retrieval
- Commitment scheme
- Cryptographically secure pseudorandom number generator

---

The world in a web browser.

### Browser security

https://en.wikipedia.org/wiki/Browser_security

> Browser security is the application of Internet security to web browsers in order to protect networked data and computer systems from breaches of privacy or malware. 

Maybe it would be caused by JavaScript or Adobe Flash.

---

There are no trusted things.

https://en.wikipedia.org/wiki/Browser_security#Security

- Operating system is breached and malware is reading/modifying the browser memory space in privilege mode.
- Operating system has a malware running as a background process, which is reading/modifying the browser memory space in privileged mode.
- Main browser executable can be hacked.
- Browser components may be hacked.
- Browser plugins can be hacked.
- Browser network communications could be intercepted outside the machine.

---
@title[Web application]

### Web application security

https://en.wikipedia.org/wiki/Web_application_security#Security_threats

- Injection
- Broken Authentication
- Sensitive Data Exposure
- XML External Entities (XXE)
- Insecure Direct Object References
- Security Misconfiguration
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Using Components with Known Vulnerabilities
- Insufficient Logging and Monitoring

---

Second, you should always monitor your system and update your security policies. In other words,

- Construct and operate a continuous monitoring system,
- Build a process or a system that can respond quickly.

They always attack in new ways.

---

### Web application firewall

https://en.wikipedia.org/wiki/Web_application_firewall

> A web application firewall (or WAF) filters, monitors, and blocks HTTP traffic to and from a web application. By inspecting HTTP traffic, it can prevent attacks stemming from web application security flaws, such as SQL injection, cross-site scripting (XSS), file inclusion, and security 

---
@title[Example]

### Example
