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

- USB devices and related information are logged in Windows Registry. So when a USB is connected to a Windows device, certain details are recorded too. The USB device information can be found in the “SYSTEM\CurrentControlSet\Enum\USBSTOR” Registry key.

- A friendly name is a human-readable name used to identify a device, application, file, certificate, or other IT asset instead of its technical identifier.

  
```bash
index=botsv1 host=we8105desk sourcetype=WinRegistry friendlyname
| table registry_value_data
| dedup registry_value_data
```

<img width="1335" height="410" alt="image" src="https://github.com/user-attachments/assets/95ed831f-d341-4558-a559-07e83cc61353" />


---

## #206    

Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?  
**Answer:**  
```bash
192.168.250.20
```

**Analysis:**

- There are Common protocols used for file transfers include **FTP, SMB, and HTTP**, so we will filter by one of them.

```bash
index="botsv1" src_ip=192.168.250.100 sourcetype="stream:smb"
```
<img width="1323" height="791" alt="image" src="https://github.com/user-attachments/assets/886e3f37-f422-4b36-a215-e031ade4c700" />

---

## #207    

How many distinct PDFs did the ransomware encrypt on the remote file server?    
**Answer:**  
```bash
257
```

**Analysis:**

- After identifying the **IP address of the file server**, we will investigate to determine the hostname .

```bash
index=botsv1 192.168.250.20
```

<img width="1899" height="480" alt="image" src="https://github.com/user-attachments/assets/f10a149a-7a72-472a-8265-e1b26b95ed9f" />


- We will modify the query to filter for events from the host `we9041srv` and identify files with a **`.pdf` file extension**.

```bash
index=botsv1 host=we9041srv *.pdf
```

<img width="720" height="531" alt="image" src="https://github.com/user-attachments/assets/0b218bb9-0a9d-4d38-ac1d-6ba081f8f0ce" />

- “Relative_Target_Name” field contains the “pdf” files.  
- The `dc` function of `stats` is used to **count the distinct values** in the identified field. This ensures that duplicate file entries are not counted multiple times.

```bash
index=botsv1 host=we9041srv *.pdf
| stats dc(Relative_Target_Name) 
```

<img width="641" height="334" alt="image" src="https://github.com/user-attachments/assets/b7ff1472-b1e2-4dc4-9ca3-1979b9237b7b" />


---

## #208    

The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?  
**Answer:**  
```bash
3968
```

**Analysis:**

- Embrace your sysmon data. Search for a command issued by the infected device and use the ParentProcessId, and ParentCommandLine, to track down the parent process id of them all.  

```bash
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" vbs 121214.tmp
```

<img width="690" height="360" alt="image" src="https://github.com/user-attachments/assets/6f50438c-5c0e-40bb-9b41-57aa9ab170b2" />

---

## #209    

The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?  
**Answer:**  
```bash
406
```

**Analysis:**

- Let's use the PC hostname of Bob smith as we identified before along with sysmon as sourcetype.  
- Then query all text files within Bob Smith’s directory, using the filter “TargetFilename”.

```bash
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" host=we8105desk TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt" 
| stats dc(TargetFilename)
```

<img width="1195" height="372" alt="image" src="https://github.com/user-attachments/assets/15b49125-f6d7-4a45-be22-64030a7b6e3d" />

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

- The file has a `.jpg` extension, indicating that it is intended to be a JPEG image. However, **steganography** is a technique used to hide malicious or sensitive data inside an otherwise normal-looking file, such as an image. In this case, the JPG file was used to conceal **malicious content**.


---
---




