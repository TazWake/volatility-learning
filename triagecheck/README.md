# Triagecheck

This volatility plugin is designed to quickly parse the process list and identify some **obvious** signs of malicious activity. It is not designed to act as an indepth assessment tool and works best for investigators looking to triage multiple platforms quickly. 

The plugin highlights the following events:
+ CSRSS - there should only be one instance and it should run from the system32 folder
+ SERVICES - this should be running from system32
+ SVCHOST - check for impersonation (e.g. scvhost / svch0st etc)
+ LSASS - there should only be one instance and it should be running from system32

## How to use triagecheck
1. Download the file to a local plugin store.
2. Invoke volatility calling the plugin.

## DFIR Notes
This tool is a high level triage for some obvious attacks. It is ideally used if you are trying to triage multiple systems or believe there is a risk that malware may be impersonating legitimate critical processes.