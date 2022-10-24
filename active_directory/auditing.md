# Auditing

- [Tools][#tools)
	- [ADExplorer](#adexplorer)
	- [PingCastle](#pingcastle)
	- [Group3r](#group3r)
	- [ADRecon](#adrecon)
	- [Purple-Knight](#purple-knight)
	- [Lepide](#lepide)

# tools

## ADExplorer

From Sysinternal Suite.

At the very first menu, we can simply press Enter and access with our user.

To create a snapshot of our domain: File -> Create Snapshot.

## PingCastle

https://www.pingcastle.com/

Run from CLI.

Default option (healthcheck) will give us a report in HTML format.

```
|:.      PingCastle (Version 2.10.1.0     1/19/2022 8:12:02 AM)
|  #:.   Get Active Directory Security at 80% in 20% of the time
# @@  >  End of support: 7/31/2023
| @@@:
: .#                                 Vincent LE TOUX (contact@pingcastle.com)
  .:       twitter: @mysmartlogon                    https://www.pingcastle.com
Select a domain or server
=========================
Please specify the domain or server to investigate (default:INLANEFREIGHT.LOCAL)

Free Edition of PingCastle 2.10.0 - Not for commercial use
Starting the task: Perform analysis for INLANEFREIGHT.LOCAL
[9:15:38 AM] Getting domain information (INLANEFREIGHT.LOCAL)
[9:15:38 AM] Gathering general data
[9:15:39 AM] Gathering user data
[9:15:40 AM] Gathering computer data
[9:15:40 AM] Gathering trust data
[9:15:59 AM] Gathering privileged group and permissions data
[9:15:59 AM] - Initialize
[9:15:59 AM] - Searching for critical and infrastructure objects
[9:16:00 AM] - Collecting objects - Iteration 1
[9:16:00 AM] - Collecting objects - Iteration 2
[9:16:00 AM] - Collecting objects - Iteration 3
[9:16:00 AM] - Collecting objects - Iteration 4
[9:16:00 AM] - Collecting objects - Iteration 5
[9:16:00 AM] - Collecting objects - Iteration 6
[9:16:00 AM] - Collecting objects - Iteration 7
..
```

## Group3r

https://github.com/Group3r/Group3r

Group3r must be run from a domain-joined host with a domain user (it does not need to be an administrator), or in the context of a domain user (i.e., using runas /netonly)

```
C:\htb> group3r.exe -f <filepath-name.log> 
```

## ADRecon

https://github.com/sense-of-security/ADRecon

```
PS C:\Tools\ADRecon> .\ADRecon.ps1
[*] ADRecon v1.1 by Prashant Mahajan (@prashant3535)
[*] Running on INLANEFREIGHT.LOCAL\ACADEMY-EA-MS01 - Member Server
[*] Commencing - 07/15/2022 09:19:11
[-] Domain
[-] Forest
[-] Trusts
[-] Sites
[-] Subnets
[-] Default Password Policy
[-] Fine Grained Password Policy - May need a Privileged Account
[-] Domain Controllers
[-] Users - May take some time
[-] User SPNs
[-] PasswordAttributes - Experimental
[-] Groups - May take some time
[-] Group Memberships - May take some time
[-] OrganizationalUnits (OUs)
[-] GPOs
[-] gPLinks - Scope of Management (SOM)
[-] DNS Zones and Records
[-] Printers
[-] Computers - May take some time
..
```


## Purple-Knight

https://www.purple-knight.com/

## Lepide

https://www.lepide.com/
