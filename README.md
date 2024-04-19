# WinLogs
Bad Powershell to quickly setup windows event logging on malware labs.

## Why?
I got tired of fiddling with these settings manually

Log-MD http://www.log-md.com/ told me to

http://www.malwarearchaeology.com/ good windows loging resource.

I also gave the backup file to Desktop Services at work and said GO HAM

## What?
This .ps1 will download the \Windows 10 TH2 Security Baseline.zip

  Extract this zip in pwd
  
  Create a profile.ps1 and add two lines to it
  
  set powershell log size
  
  Run LGPO.EXE (that was in the zip file) to restore the Backup GPO file

## How?
  Open a powershell window as admin
  Have your execution policy set
  
  .\RunMe.Ps1

## Where?
  Should work on all Windows 7 and up systems. Including Server.

## Disclaimer
  This works for me, will it work for you? 
  
        Who knows!
        
  I would not run on a product system or a work computer.
  
  I build this for temporary systems I plan on running bad things on. 

## Resources

http://www.log-md.com/

http://www.malwarearchaeology.com/

https://blogs.technet.microsoft.com/secguide/2016/01/22/security-baseline-for-windows-10-v1511-threshold-2-final/


