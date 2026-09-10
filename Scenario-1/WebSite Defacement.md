## Overview

Today is Alice's first day at the Wayne Enterprises' Security Operations Center. Lucius sits Alice down and gives her first assignment: A memo from Gotham City Police Department (GCPD). Apparently GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com hosted on Wayne Enterprises' IP address space has been compromised. The group has multiple objectives... but a key aspect of their modus operandi is to deface websites in order to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com. (the personal blog of Wayne Corporations CEO) was really compromised.

## Investigation

## #101  

What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?  
**Answer:**  
```bash
40.80.148.42
```
**Analysis:**


---

## #102  

What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.  
**Answer:**  
```bash
Acunetix
```

**Analysis:**



---

## #103 

What content management system is imreallynotbatman.com likely using?  
**Answer:**  
```bash
joomla
```


**Analysis:**

---

## #104  

What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?  
**Answer:**  
```bash
poisonivy-is-coming-for-you-batman.jpeg
```


**Analysis:**

---

## #105  

This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?  
**Answer:**  
```bash
prankglassinebracket.jumpingcrab.com
```

**Analysis:**



---

## #106  

What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?  
**Answer:**  
```bash
23.22.63.114
```

**Analysis:**


---

## #108  

What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?  
**Answer:**  
```bash
23.22.63.114
```

**Analysis:**


---

## #109  

What is the name of the executable uploaded by Po1s0n1vy?   
Answer guidance: Please include file extension. (For example, "notepad.exe" or "favicon.ico")  
**Answer:**  
```bash
3791.exe
```

**Analysis:**


---

## #110  

What is the MD5 hash of the executable uploaded?  
**Answer:**  
```bash
AAE3F5A29935E6ABCC2C2754D12A9AF0
```

**Analysis:**


---

## #111  

GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.  
**Answer:**  
```bash
9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8
```

**Analysis:**

---

## #112  

What special hex code is associated with the customized malware discussed in question 111?  
Answer guidance: It's not in Splunk!!
**Answer:**  
```bash
53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21
```

**Analysis:**


---

## #114  

What was the first brute force password used?  
**Answer:**  
```bash
12345678
```


**Analysis:**

---

## #115  


One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?  
**Answer:**  
```bash
Yellow
```

**Analysis:**


---

## #116  

What was the correct password for admin access to the content management system running "imreallynotbatman.com"?  
**Answer:**  
```bash
batman
```

**Analysis:**


---

## #117  

What was the average password length used in the password brute forcing attempt?  
Answer guidance: Round to closest whole integer. For example "5" not "5.23213"  
**Answer:**  
```bash
6
```

**Analysis:**


---

## #118  


How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login?  
Answer guidance: Round to 2 decimal places.  
**Answer:**  
```bash
92.17
```

**Analysis:**




---

## #119  

How many unique passwords were attempted in the brute force attempt?  
**Answer:**  
```bash
412
```

**Analysis:**


---

## Conclusion:






