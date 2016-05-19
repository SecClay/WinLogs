# WinLogs
Bad Powershell to quickly setup windows event logging on malware labs.

## Why?
I got tired of fiddling with these settings manually
Log-MD http://www.log-md.com/ told me to set these settings
http://www.malwarearchaeology.com/ good windows loging resource.
I also gave the backup file to Desktop Services at work and said GO HAM

## contents
  RunMe.ps1 - really bad powershell
  {00AB999A-5370-4DB3-A10B-2C5C3FBA3993} - gpobackup goop from server 2012 

## What?
This .ps1 will download the \Windows 10 TH2 Security Baseline.zip
  Extract this zip in pwd
  Create a profile.ps1 and add two lines to it
  set powershell log size
  Run LGPO.EXE (that was in the zip file) to restore the Backup GPO file

## How?
  .\RunMe.Ps1

## Disclaimer
  This works for me, will it work for you? Who knows!
  I would not run on a product system or a work computer
  I build this for VM
