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

```bash
index="botsv1" imreallynotbatman.com
```
<img width="720" height="354" alt="image" src="https://github.com/user-attachments/assets/1114c67e-da69-40fa-a3b5-84676c291c4e" />

- Searching for `imreallynotbatman.com` revealed three source IP addresses (SRC_IPs). One of the addresses was private so excluded from further analysis.
- The remaining two were public IP addresses. Based on the observed request/traffic volume, we will go with the public IP address generating the highest amount of traffic.

---

## #102  

What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.  
**Answer:**  
```bash
Acunetix
```

**Analysis:**  

```bash
index="botsv1"  src_ip="40.80.148.42" source="stream:http" imreallynotbatman.com
```

<img width="1320" height="784" alt="image" src="https://github.com/user-attachments/assets/bdd39ff2-94da-4a99-b64c-0a2c563e779d" />

- When looking in the events one by one you will found `Acunetix Web Vulnerability Scanner - Free Edition` alot.

---

## #103 

What content management system is imreallynotbatman.com likely using?  
**Answer:**  
```bash
joomla
```

**Analysis:**  
<img width="1320" height="784" alt="image" src="https://github.com/user-attachments/assets/8d574dad-682a-4c4b-a320-4356b184bb29" />

- Additionally, within the same event, we identified the **management system being used**.

---

## #104  

What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?  
**Answer:**  
```bash
poisonivy-is-coming-for-you-batman.jpeg
```

**Analysis:**

- Since the file is hosted on the web server, we will search using the **server's IP address** so, our first step is to identify the web server's IP address. (192.168.250.70)  

```bash
index="botsv1" imreallynotbatman.com src_ip="40.80.148.42"
```

<img width="779" height="322" alt="image" src="https://github.com/user-attachments/assets/690fa01e-def5-43cf-837d-e2d711a5a1a0" /> 


- We are looking for a **malicious file that was downloaded**. By filtering for `stream:http` as the source type and using the victim's IP address as the source IP, we can narrow the search to HTTP traffic.  

```bash
index="botsv1"  src_ip="192.168.250.70" sourcetype="stream:http"
```

<img width="763" height="171" alt="image" src="https://github.com/user-attachments/assets/21cdc90a-78f0-4e76-9f58-994be54a8c00" />
<img width="617" height="365" alt="image" src="https://github.com/user-attachments/assets/23dc29da-0a8e-49cb-bdad-91720bbd0a29" />

- The search returns only **8 events**. Examining the `uri`, `uri_path`, and `url` fields reveals the same result across the events, making it easier to identify the requested resource.
- We can also search the **src_headers**, since the file download request uses the HTTP `GET` method.




---

## #105  

This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?  
**Answer:**  
```bash
prankglassinebracket.jumpingcrab.com
```

**Analysis:**


- We will use the URI identified in the previous question to continue.
  
```bash
index="botsv1"  src_ip="192.168.250.70" sourcetype="stream:http" uri="/poisonivy-is-coming-for-you-batman.jpeg"
```

- The search returns only **two events**. After inspecting these events, we can identify the **(FQDN)** associated with the activity.

  <img width="948" height="899" alt="image" src="https://github.com/user-attachments/assets/4725a763-8c3a-4224-b73f-73f81b945614" />


---

## #106  

What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?  
**Answer:**  
```bash
23.22.63.114
```

**Analysis:**

- From the previous Question we can find the IP-Address easily.  

<img width="1338" height="981" alt="image" src="https://github.com/user-attachments/assets/1f542865-6f47-4e4a-acca-46c7274a2812" />


---

## #108  

What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?  
**Answer:**  
```bash
23.22.63.114
```

**Analysis:**    

- We will search with the webserver as the destination while the brute force is a post request, so we will filter by it and the form_data to see the user&passwd output.

  
```bash
index="botsv1"  dest_ip="192.168.250.70" sourcetype="stream:http" http_method=POST
| table  src_ip, form_data, uri
```
<img width="1872" height="876" alt="image" src="https://github.com/user-attachments/assets/539e24ee-56f5-44c3-b7c6-16454127eef4" />


---


## #109  

What is the name of the executable uploaded by Po1s0n1vy?   
Answer guidance: Please include file extension. (For example, "notepad.exe" or "favicon.ico")  
**Answer:**  
```bash
3791.exe
```

**Analysis:**

- As file is uploaded so the webserver will be the destination and will be a post request to the server then search with (*.exe).
- The output will only be 3 events and by examining them you will easily find the .exe file.

```bash
index="botsv1"  dest_ip="192.168.250.70" sourcetype="stream:http" http_method=POST *.exe
```

<img width="1531" height="382" alt="image" src="https://github.com/user-attachments/assets/142fd886-0795-46e2-a3fe-ff87b9e6f59b" />

---

## #110  

What is the MD5 hash of the executable uploaded?  
**Answer:**  
```bash
AAE3F5A29935E6ABCC2C2754D12A9AF0
```

**Analysis:**

* We first searched for `3791.exe`.
* We then applied the `sysmon` source filter to narrow the results to Sysmon events.
* Next, we filtered by `EventID=1`, which represents **process creation** events.
* The search returned **5 events**. By further filtering the `cmdline` field, we identified the execution of `3791.exe` and retrieved its **MD5 hash**.

```bash
index="botsv1"  3791.exe source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 cmdline="3791.exe"
```

<img width="1232" height="421" alt="image" src="https://github.com/user-attachments/assets/67f68cf2-35a8-4d09-bf76-87e5f24d2337" />
<img width="1884" height="766" alt="image" src="https://github.com/user-attachments/assets/51599343-089b-48ce-8043-135b0659ed51" />

---

## #111  

GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.  
**Answer:**  
```bash
9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8
```

**Analysis:**

- We will use **VirusTotal** to search for the attacker IP address and determine whether it is associated with any **known malicious activity or malware**.

<img width="1325" height="792" alt="image" src="https://github.com/user-attachments/assets/0766c963-a36f-4fe4-a732-08703caa26e5" />
<img width="1557" height="812" alt="image" src="https://github.com/user-attachments/assets/2f91481c-16c9-4404-b15e-3bb7992f95fc" />

---

## #112  

What special hex code is associated with the customized malware discussed in question 111?  
Answer guidance: It's not in Splunk!!
**Answer:**  
```bash
53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21
```

**Analysis:**

- The solution by the community on virus total.

  
<img width="1822" height="240" alt="image" src="https://github.com/user-attachments/assets/f7c4d8e1-5038-4cf8-bc89-a9c62445c482" />


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






