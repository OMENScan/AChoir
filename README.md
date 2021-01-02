# AChoir
Windows Live Artifacts Acquisition Scripting Framework

# Brief Description:
Every Incident Responder eventually comes to the conclusion that they need to 
script their favorite Live Acquisition utilities.

I have seen these scripts written in numerous scripting languages - but oddly 
enough, all of these scripts tend to use many of the same freely available 
utilities - To do mostly the same things.

It often takes an Incident Responder several years, along with lots of trial 
and error to settle on a set of utilities (and options) that both work and 
that provide relevant information on useful forensic artifacts.

And even though Responders often use the same utilities and are scripting them 
in largely the same way, each Responder has to go through the same pain of 
building their own script in their (not so) favorite scripting language - 
figuring out how to quickly and consistently gather the artifacts of most value. 

Achoir is a Framework/Scripting Tool to standardize and simplify that process.


#Versions (So Far):

AChoir v0.01
- First Version  (05/30/15)    

AChoir v0.02
- Add Variables: &Dir &Fil &Acq &Win  

AChoir v0.03
- Add Hashing

AChoir v0.04
- Add FOR:, &FOR, &NUM  Looping  

AChoir v0.05
- Add CKY:, CKN:, RC=:, RC!:, RC):, RC(:, END:, &CHK, &RCD

AChoir v0.06
- Add Logging

AChoir v0.07
- Add /BLD (Build.Acq), /DRV:, &Prc, 32B:, 64B:, BYE:  

AChoir v0.08
- Hash Program before running,Set Artifacts ROS 

AChoir v0.09
- Create Index.html for Artifact Browsing  

AChoir v0.10
- Mapping External Drives - Set to the ACQDir   

AChoir v0.11
- New &Map variable and INI: action
- INP: action and &Inp variable (Console Input) 

AChoir v0.13
- New &Tmp is the Window %Temp% variable   
- New CPY: Action to copy files  
- New &FNM variable - Each &FOR File Name  

AChoir v0.20
- Lets call this 2.0-Lots of Code improvements  

AChoir v0.21
- Fix GMT DST idiosyncracy  

AChoir v0.22
- New ARN: Action - Parse the Run Key and copy the Autorun EXEs   

AChoir v0.23
- /MNU Command Line Option Runs Menu.ACQ   

AChoir v0.24
- Expand the ARN: routine to recognize WOW64 and System32/sysnative redirection
  
AChoir v0.25
- More improvements to Run Key Extract

AChoir v0.26
- Expand system variables %variable%  

AChoir v0.27
- More improvements in remote acquisition (Map) 

AChoir v0.28
- Add /MAP:  /USR:  and  /PWD:  command lines, and MAP:  USR:  and  PWD:  INI file Actions to enable Mapping for Remote Acquisition 

AChoir v0.29
- Add ADM:Check and ADM:Force to check OR enforce that AChoir be run from an ADMIN ID   
- Converted to MSVC - Also replaced libCurl with MS WinHTTP APIs
 
AChoir v0.30
- Improve CPY: - Prevent Overwriting Files 

AChoir v0.31
- Start and End Time Stamps and &Tim variable   

AChoir v0.32
- Changes to support 32 and 64 Bit versions!    

AChoir v0.33
- Turn On/Off USB Write Protect  

AChoir v0.34
- Internal Code Cleanup

AChoir v0.35
- Add DRV: Action to Set &Drv    

AChoir v0.36
- Add Variables 0-9 (VR0: - VR9:) (&VR0 - &VR9)
- Fix Win7 "Application Data" Path Recursion Anomoly
   
AChoir v0.37
- Remove DST Calculation - Add Checks to CPY:   

AChoir v0.38
- New DST Convergence Code  

AChoir v0.39
- Add LBL: and JMP: for Conditional Execution   

AChoir v0.40
- Add XIT: (Exit Command - Run on Exit)    

AChoir v0.41
- Offline Registry parse of AutoRun Keys for DeadBox analysis 

AChoir v0.42
- Change HTML display to only Root Folder  

AChoir v0.43
- Match DLL Delay Loading to &Dir Directory

AChoir v0.44
- Fix root folder edge case 

AChoir v0.50
- Add CMD: - Like SYS: But uses a CMD.Exe shell In &Dir - Check Hash for AChoir ReactOS Shell 

AChoir v0.55
- Add LST: - Looping Object (&LST) that reads entries from a file.  Also Add SID (file  owner) copy on the CPY: command.   

AChoir v0.56
- Improve Privileges Message Display  

AChoir v0.57
- Fix Priv Bug & Add better Error Detection

AChoir v0.75
- Add NTFS Raw Copy (NCP:)  
  - NCP:(Wilcard File Search) (Destination Dir)
- Additional Recursion Error Checking 

AChoir v0.80
- NTFS Raw Reading now support Attribute List (Multiple Cluster Runs/Fragmented Files) 

AChoir v0.81
- More NTFS Raw Read honing 

AChoir v0.82
- Add MAX: - Max File Size (& Mem Usage)   

AChoir v0.83
- Add RawCopy to ARN:  

AChoir v0.85
- Can now Read POSIX file names & Hard Links    

AChoir v0.89
- Large File (GreaterThan 1GB) Support

AChoir v0.90
- ADD HKCU Parsing for ARN: 

AChoir v0.91
- Edge case exit Bug Fix    

AChoir v0.92
- Sig:(Typ=xxxx) Load File Type, Hex Signature
- NCS: NTFS Copy by Signature
   - Used together to copy Files by Signature
    
AChoir v0.93
- Refactored some SQLite Code to avoid random Heap Corruption issues   

AChoir v0.95
- FINALLY Fix Abend Bug in Large File Support
   - Got rid of the other attempts to fix it  
- NOTE: v0.95 will be slower than previous Versions. I opted for slower and safer code with a smaller memory footprint.    

AChoir v0.96
- Clean Up some of the code, improve output.    

AChoir v0.96a
- Cosmetic changes to Index.htm  

AChoir v0.97
- Add Colors, Minor Bug Fixes    

AChoir v0.98
- CPS: Copy by Signature (Standard Win32 API)   
   - Used with SIG: to copy Files by Signature
   - Not Recommended for Locked/System Files    
- Tighten Application Data recursion to 2 lvls  
- /Con or /ini:Console - Console as Input File  

AChoir v0.98a
- Various improvements to Interactive Mode 
- Replace conditional statements with messages
- add INI:Console to Scripting 
- Improve switching between Script and Interactive Modes 

AChoir v1.0
- Cosmetic USB Message Changes   
- HTTP Get Bug Fixes, Fix &Acq dblSlash    
- Add Optional Case & Evidence Name/Number Input
- CSE:GET and CSE:SAY  
- /CSE Argument to Get Case Information    
- VCK:(x:\)  NTFS, FAT32, CDFS, Other, None
- &VCK - Contains Results of VCK:
- EQU:(s1) (s2) - Are S1 and S2 Equal?
- NEQ:(s1) (s2) - Are S1 and S2 NOT Equal? 
- Support Indenting (spaces or Tabs)  
- DSK:(type)  Set &DSK looping variable to 
- Types: Removable, Fixed, Remote, CDROM 
   - &DSK - Looping Var Contains Disk that match

AChoir v1.1
- Peppered Flush STDOUT buffers for better PSExec Display (Remote Acq) 
- SHR:(Path) (Name) - Create a Local Share
- SHD:(Name) - Delete a Local Share 

AChoir v1.2
- Add /USR:? and /PWD:? - Query MAP USR and PWD 
- Replaced getch() with getchar().  This is because PsExec does not work with getch().
   - PsExec also does not work with SetConsoleMode so there is no way to do hidden/masked password input.

AChoir v1.3
- Implement NTP Client for Querying Time Drift  
- Fix minor display bug when using &Tim

 AChoir v1.4
- New Actions to Hide and Reconnect the Console 
   - CON:Hide and CON:Show 
- SLP:(Sec) Sleep for (Sec)Seconds  

AChoir v1.5
- Add /VR0: -/VR9: Command Line Parameters
- When BaseDir changes, change Windows CWD too  
- New Redaction Routine for PWD: EXE: CMD:

 AChoir v1.6
- Add EXA: and EXB:  (Asyn & Background EXe) 

AChoir v1.7
- Fix DSK: &DSK bug for Remote Collections
- File not being properly closed causes loop.

AChoir v1.8
- Recognize Compressed Files, and allow them to be copied by the OS API to DeCompress them.
   - The Flag for this behaviour is: SET:NCP=OSCOPY or SET:NCP=RAWONLY
- Added built in Support for WOW64 file redirection of X86 binCopy of SYSTEM32 (sub) directories. This was needed for switching from rawcopy to bincopy - plus its a good general feature anyway.

 AChoir v1.9
- Recognize Compressed Size

AChoir v1.9a
- More Comressed Files Support

AChoir v2.0
- Add LZNT1 Decompress Routine
   - Flag behaviors have changed:  
   - SET:NCP=NODCMP - NoDecompression 
   - SET:NCP=DECOMP/RAWONLY - LZNT1 Decompress 
   - SET:NCP=OSCOPY - Do OS/API copy on Decomp Err

AChoir v2.1
- Add App Compat Manifest - For 8.1 and above comaptibility  
- Add new Conditional Logic on Windows Version  
   - VER:WinXP, WinXP64, Vista, Win7, Win8, Win8.1
   - Win10
   - Win2000, Win2003, Win2008, Win2008R2, Win2012, Win2012R2, Win2016

AChoir v2.2
- Add Ver: Client, and Server checks

AChoir v2.3
- LZNT1 Bug fixes by Yogesh Katri

 AChoir v2.4
- Update Offreg, and fix Edge Case of Short FN without a Long FN in $MFT record.

AChoir v2.5
- Partial Back out of LZNT1 mod that negatively impacted $MFT Resident File extraction 

AChoir v2.6
- Fix Duplicate File copy due to multiple MFT Records for a file (Hard Links)  

AChoir v2.7
- Additional Messages for Looping

 AChoir v2.8
- Add ability to preserve Paths in CPY: and NCP:
   - Set:CopyPath=Full/Partial/None 
   - Allow ACQ: and DIR: to create nested paths

AChoir v2.9
- Fix FOR: without backslash (Current Dir only)
- Move Get: to its own routine to allow new /Get: option - This will function as a way to allow AChoir to load an INI file remotely 

AChoir v3.0
- Added &MEM (Total memory), &DSA (Disk Avail)
- Added N>>:, N<<:, and N==: For NUMBERS ONLY comparison. Note: All numbers are converted internally to longlong (atoll)
   - These can be used together to see if we have enough disk space to capture memory i.e. N>>:&DSA &MEM  

AChoir v3.1
- Expand Available Disk Checking into File Copy/Extract

AChoir v3.2
- &DSA Should Really Point to the &ACQ Drive in case we use MAP:  
-  Added Experimental Sysloog Output and new Settings:
   - SET:SYSLOGS=(Syslog Server IP)
   - SET:SYSLOGP=(Syslog Port)  
  - -SET:SYSLOGL=None, Min, Max

AChoir v3.3
- Expand syslogging  

AChoir v3.4\
- Add Set:MapErr=Continue, Fail, Query)

AChoir v3.5
- Add &CNR, &CN0-CN9, CN++, CN-- (Counters), and &Acn (Acquisition Name)
- Add Set:Trim=(Yes) or (No) (Default is Yes)
   - Trims &FOR and &LST since DOS File Redirects OFTEN add erroneous spaces

AChoir v3.6
- Add SET:DELIMS= (Sets the Parsing Delimiters)
   - &LS0-&LS9 (Parses the first 10 Cols in &LST)
   - &FO0-&FO9 (Parses the first 10 Cols in &FOR)

AChoir v3.7
- Add WildCard to CPY: (No Longer needs FOR: to do multiple file copy)
- Add SET:CopyDepth=nn - Set Maximum Directory for CPY: (Does not work win NCP:) - This will help speed up copying by preventing unnecessary depth (Default is 10 SubDirs)

AChoir v3.8
- Better mkdir Processing (Error Correction)
- Better Support for MAP: (Sets Target Dirs)
- Set:Cache=(local) or (Movable) - Speed enhancement to keep the Cache local to the target machine - Use with caution.

AChoir v3.9
- Cut down on the Display Messages
- CON:MSGLevel=(min), (std), (max), (debug) (min=What it is doing, std= What it is doing and results (default), max= What it is doing and expanded results, debug= Same as max for now)

AChoir v4.0
- No changes - Releasing v4.0 in honor of the Mr. Robot Season 4 premier 10/06/2019

AChoir v4.1
- Add OPN: Opens a file for output, if a file is already OPN, it will be closed. Only one file can be OPN at a time.
- Add OUT: Action - Appends a string to the OPN: File
- Expand parsing to &LSA - &LSP and &FOA - &FOP
- Add Experimental Unicode File Processing
   - Only UTF-16 (Big & Little Endian)

AChoir v4.2
- Make Log File consistent (set to ACQName)

AChoir v4.3
- Added &HST Variable (Host Name)

AChoir v4.4
- Improve Parsing to recognize dbl-quotes

AChoir v4.5
- Updates carried over from AChoirX 10.00.38
- Change conditional logic to only count a single occurance of &FOR and &LST comparisons. This prevents the need for multiple END: statements  - Multiple comparisons only get a single hit if ANY match is found. THIS IS IMPORTANT!! Wherever &FOR and &LST are used in CONDITIONAL LOGIC - A SINGLE HIT WILL BE TRUE.  To Test for INDIVIDUAL cases use a specific check and NOT a Check Against a list (&LST, &FOR).
- Expand &FOR and &LST Support to more Actions
- Add HSH:<Filename> Will put the File hash in the &HSH Variable (Only supports a single File for now)
- Implement END:Reset to clear any Dangling ENDs.  Use Judiciously. 


# Quick Start (tl;dr):
The quickest way to get started with AChoir is to download the Achoir-Inst.exe 
file, run it, and allow it to build the default AChoir Toolkit.  

If you want to buid the toolkit onto an external USB drive, simply install Achoir 
to your external USB drive, and let the Install program run the build process 
from there.  Achoir will Install and build the toolkit onto the Drive and 
Directory it is installed to. This process also works if you want to install/run
AChoir from a network share.
