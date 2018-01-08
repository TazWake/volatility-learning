# Volatility-Learning
I am in the process of learning how to create volatility plugins. This repo will be used as a storage platform for them.

In the event that anything of actual value is created (rather than just a rework of existing ones as I try to understand the commands) it will be migrated to a new location.

The majority of ideas will come from [The Art of Memory Forensics](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics%3A+Detecting+Malware+and+Threats+in+Windows%2C+Linux%2C+and+Mac+Memory-p-9781118825099), which is possibly the best single source of knowledge on this topic.

## RAMSCAN
The first volatility plugin is `ramscan.py`. 
This plugin lists running processes with PID and Parent PID, Command Line used to invoke the process and a check to see what the VAD settings are. If the VAD is set to Read, Write, Execute it is marked as suspicious.

### How to use ramscan.py
1. Download the plugin to a folder on your local machine.
2. Invoke volatility calling the plugins folder before anything else. eg: `python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} ramscan`
3. A more useable method is to set an output format and output file as the data presented by this plugin can quickly fill a console window.

*recommended use*

`python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} ramscan --output=html --output-file=ramscan.html`

### Example output

```
Name           PID  Parent Command Line   VAD               
System            4      0                                   
smss.exe        504      4 \SystemRoot\temp\smss.exe
conhost.exe    6248    748 \??\C:\WINDOWS\system32\conhost.exe "9131723291973856416-156581232056986786412445124951738786652-244451647283318875 Suspicious RWX VAD
scPopup.exe    6284   4616 "C:\Program Files\Xerox\scPopup.exe" /s /k /t /g Suspicious RWX VAD
GROOVE.EXE     6384   4616 "C:\Program Files\Microsoft Office 15\root\office15\GROOVE.EXE" /RunFolderSync /TrayOnly  Suspicious RWX VAD
mobsync.exe    6672    936 C:\WINDOWS\System32\mobsync.exe -Embedding Suspicious RWX VAD
ucmapi.exe     5748    936 "C:\Program Files\Microsoft Office 15\Root\Office15\UcMapi.exe" -Embedding Suspicious RWX VAD
powershell.exe 5772   6188 powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoACgAbgBlAHcALQBvAGIA...ACcAaAB0AHQAcAA6AC8ALwAxADIANwAuADAALgAwAC4AMQA6ADUAMgA4ADAAOAAvACcAKQApAA== Suspicious RWX VAD
```
### IR Use
* Look for command execution from unusual locations
* Look for suspicious command execution: Eg encoded Powershell
* Look for memory sections which allow read-write-execute

## CMDCHECK

This volatility plugin scans memory for `cmd.exe` execution and checks the standard handles.

If cmd.exe is being used for data exfiltration (or other unwanted activity) it is likely that the handles will change. This is a good way to check for backdoors / modification (Pages 230 - 232 of The Art of Memory Forensics).

### Use

1. Download the plugin to a local filesystem
2. Run the plugin against a memory image: `python vol.py --plugins={path/to/plugin} --profile={image profile} -f {memory.img} cmdcheck`
3. Any deviation from the norm will be annotated with **!*!**
4. Note: *This does not work if the process has exited memory*

### IR Notes

* Modified handles in cmd.exe is an indicator of malice.

## Fast VAD Scan

This is a volatility plugin, similar to malfind, which looks at the number of pages committed and the VAD settings. It **does not** extract files so may run faster.

When executed this plugin will return the process name and PID for any process which has more than 30 pages committed and RWX set.

### How to use Fast VAD Scan

1. Download the plugin to a local filesystem location
2. Run volatility calling the plugin: `python vol.py --plugins={path/to/plugins} --profile={image profile} -f {filename} fastvadscan`
3. Review output and determine if any files warrant further investigation

### IR Notes

* This is a triage tool and works best if you have suspicious files
* It can narrow down files for further analysis
* If file extraction is required, run malfind

## Path Check

This plugin scans the capture and identifies an executables which appear to have been loaded from a temp, download or user location. The choice of locations is arbritrary and can be adjusted to suit the investigation.
The location matching is case insensitive so will match `temp`, `Temp` and `TEMP` in a path.

### How to use Path Check

1. Download the plugin to a local files store
2. Invoke volatility (with the plugins folder before anything else) calling pathcheck. For example: `python vol.py --plugins={path/to/plugins} --profile={profile for memory image} -f {path to image} pathcheck`
3. Review the output - processes executed from temp / download or user locations are more likely to be malware and should be subject to further investigation.

### IR Use

This tool is best used as part of the triage process to get a quick feel for what suspicious activity is on the system.

Alternatively, it can be used as part of a threat hunting review via a remote access agent (such as F-Response)
