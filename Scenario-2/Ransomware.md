## Overview

After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...

## Investigation

## #200  

What was the most likely IPv4 address of we8105desk on 24AUG2016?  
**Answer:**  
```bash
192.168.250.100
```

**Analysis:**
- First search by `we8105desk` and change the time range to 24AUG2016.

  ```bash
  index="botsv1" we8105desk 
  ```

<img width="1904" height="481" alt="image" src="https://github.com/user-attachments/assets/f3d51670-1400-4ee3-8c52-8ec37d36f0b6" />

- Then we will filter with the pc as the src then you will find its IP address easily.

  ```bash
  index="botsv1" we8105desk  src="we8105desk.waynecorpinc.local"
  ```

  <img width="1331" height="836" alt="image" src="https://github.com/user-attachments/assets/6ff7bfb0-ff6e-4109-b14c-1c18b3bef7da" />

  
---

## #201   

Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.  
Answer guidance: No punctuation, just 7 digits  
**Answer:**  
```bash
2816763
```

**Analysis:**

- Filter by suricata and then search with cerber word.

  ```bash
  index="botsv1"   cerber sourcetype=suricata
  ```

<img width="871" height="341" alt="image" src="https://github.com/user-attachments/assets/342f757a-bdaf-4b02-a7b3-620efefc4704" />
<img width="687" height="402" alt="image" src="https://github.com/user-attachments/assets/775b6822-f430-4f8e-b67f-e24769e9e5c7" />

  

---

## #202   

What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?  
**Answer:**  
```bash
cerberhhyed5frqa.xmfir0.win
```


**Analysis:**

- We will search using `stream:dns`. Since the search may return a large number of DNS queries, we can reduce the noise by excluding common domains such as `arpa`, `microsoft`, and `msn.local`, while keeping the **primary device's IP address as the `src_ip`**.

```bash
index=botsv1 src_ip="192.168.250.100" source="stream:dns" NOT query=*.arpa AND NOT query=*.microsoft.com AND NOT query=*.msn.com AND NOT query=*.info AND NOT query=*.local AND query=*.*
| table dest_ip _time query
| sort by _time desc
```

<img width="1908" height="539" alt="image" src="https://github.com/user-attachments/assets/7351a24f-a6f5-42ed-9a88-54e3e89c4086" />

---

## #203    

What was the first suspicious domain visited by we8105desk on 24AUG2016?  
**Answer:**  
```bash
solidaritedeproximite.org
```


**Analysis:**

- Change the stream to http and table to see site rquests.

  
```bash
index=botsv1 src_ip="192.168.250.100" source="stream:http"
| table site, _time
```

<img width="1745" height="507" alt="image" src="https://github.com/user-attachments/assets/85cca687-c054-4cdc-a0fc-2aa7a43a2f0d" />


---

## #204    

During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?  
Answer guidance: Enter the number of characters (i.e.the "length") of the field.  
**Answer:**  
```bash
4490
```

**Analysis:**

- We will search using the Sysmon source and specifically look for the execution of a VBScript (.vbs) script. By inspecting the cmdline field, we can identify the command used to execute the script

```bash
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" *.vbs 
|  table CommandLine
```

<img width="1913" height="751" alt="image" src="https://github.com/user-attachments/assets/ad4170ca-b3a8-4d06-98f3-8b9a63b6b46d" />  

- To determine the **number of characters** in a field, we can use the `eval` command with the `len()` function, which returns the character length of the specified field.

```bash
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" vbs
| eval lencmd=len(CommandLine)
| table _time CommandLine, lencmd
| sort - lencmd
```

<img width="1926" height="738" alt="image" src="https://github.com/user-attachments/assets/a1621236-fb8c-4c7d-a32b-34e042452154" />


---

## #205    

What is the name of the USB key inserted by Bob Smith?  
**Answer:**  
```bash
MIRANDA_PRI
```

**Analysis:**


---

## #206    

Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?  
**Answer:**  
```bash
192.168.250.20
```

**Analysis:**


---

## #207    

How many distinct PDFs did the ransomware encrypt on the remote file server?    
**Answer:**  
```bash
257
```

**Analysis:**


---

## #208    

The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?  
**Answer:**  
```bash
3968
```

**Analysis:**


---

## #209    

The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?  
**Answer:**  
```bash
406
```

**Analysis:**

---

## #210  

The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?  
**Answer:**  
```bash
mhtr.jpg
```

**Analysis:**


---

## #211  

Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?  
**Answer:**  
```bash
steganography
```

**Analysis:**


---
---




