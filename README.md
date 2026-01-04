# digital-forensic-toolkit
This toolkit leverages Autopsy (a GUI front-end for Sleuth Kit), Sleuth Kit (command-line tools for disk analysis), Volatility (memory forensics), and FTK Imager (for evidence acquisition). These open-source or freely available tools form a robust, integrated suite for collecting and analyzing evidence from compromised systems. </br>
</br>
#**Core Components of the Toolkit**

# **1. Evidence Collection Tools**</br>
These focus on acquiring data from live or offline systems without contamination.
Imaging and Acquisition:</br>
FTK Imager (free from AccessData): Creates forensic images of drives or memory. Use it to capture full disk images in formats like E01 or DD.
dd (built-in on Linux/macOS): Command-line tool for bit-for-bit copying. Example: dd if=/dev/sda of=image.dd bs=4M conv=noerror,sync (add status=progress for monitoring).
Memdump or Volatility (for memory): Capture RAM dumps on live systems to analyze volatile data like running processes.<br></br>
#**Live System Tools:**</br>
</br>
Autopsy (open-source, GUI-based): Integrates with Sleuth Kit for live triage, hashing files, and timeline creation.</br>
EnCase (commercial, but alternatives like Magnet AXIOM exist): For comprehensive live acquisition on Windows/Linux.</br>
#**Network Evidence:**</br>
</br>
Wireshark or tcpdump: Capture network traffic logs. Use filters like tcp port 80 to isolate suspicious activity.</br>
Netcat or socat: For transferring data securely over networks during collection.</br>
#**Log Collectors:**</br>
Syslog-ng or rsyslog: Aggregate logs from multiple systems.</br>
ELK Stack (Elasticsearch, Logstash, Kibana): For scalable log ingestion and visualization.</br>
 Evidence Analysis Tools</br>
Once collected, analyze for indicators of compromise (IoCs) like malware, unauthorized access, or data exfiltration.</br>
</br>
#**File and Disk Analysis:**</br>
</br>
Sleuth Kit (command-line) and Autopsy (GUI): Parse file systems, recover deleted files, and generate timelines. Example: Use fls to list file metadata.
Bulk Extractor: Scans images for patterns like email addresses, credit cards, or hashes.
Memory and Process Analysis:
</br>
**Volatility Framework:** Analyze memory dumps for processes, network connections, and malware. Commands like volatility -f memdump.vmem pslist list running processes.
Rekall (alternative to Volatility): Similar capabilities with a focus on advanced forensics.
Malware and Artifact Analysis:</br>
</br>
**YARA:** Define rules to scan for malware signatures. Example rule: rule suspicious_exe { strings: $a = "malicious_string" condition: $a }.
VirusTotal API or ClamAV: Scan files for known threats.</br>
Strings and Hex Editors (e.g., HxD): Extract readable text or binary patterns from executables.
**Timeline and Correlation:**</br>
Plaso (log2timeline):Creates super-timelines from various logs and artifacts.
Splunk or Chronicle (for enterprise): Correlate events across systems.
**Hashing and Integrity:**</br>

Hashdeep or md5sum/sha256sum:Generate hashes to verify data integrity. Compare against known good hashes (e.g., from NIST NSRL).
#**Automation and Scripting**</br>
To streamline the toolkit, incorporate scripts for repetitive tasks.</br>
Python Scripts: Use libraries like pytsk3 (for Sleuth Kit integration) or pymem for memory analysis. Example script to hash all files in a directory:</br>
