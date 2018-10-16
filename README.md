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


#Versions (So Far)
* AChoir v0.08 - Released as Open Source at my Live Acquisition presentation 
   at BSides Las Vegas, August 2015
.. https://www.youtube.com/watch?v=NNPiSlVsA6M
* AChoir v0.09 - Added creation of Index.html for simple Artifact browsing
* AChoir v0.10 - Added Mapping to remote drives, and (re)setting the ACQDir
* AChoir v0.11 - Added &Map variable 
* ............ - Added INI: action (switches the INI File) - Used for remote acquisition
* ............ -  Added INP: action and &Inp variable (Console Input and variable)
* AChoir v0.13 - New &Tmp is the Window %Temp% variable
* ............ -  New CPY: Action to copy files
* ............ -  New &FNM variable - Each &FOR File Name
* AChoir v0.20 - Lets call this 2.0-Lots of Code improvements
* AChoir v0.21 - Fix GMT DST idiosyncracy
* AChoir v0.22 - New ARN: Action - Parse the Run Key and copy the Autorun EXEs
* AChoir v0.23 - New /MNU Switch - Run the Menu.ACQ script
* AChoir v0.24 - Expand the ARN: routine to recognize WOW64
* ............ and System32/sysnative wierdness
* AChoir v0.25 - More improvements to Run Key Extract
* Achoir v0.25b - Add WinAudit and GPResult to Scripts
* AChoir v0.26 - Expand system variables %variable%
* AChoir v0.27 - More improvements in remote acquisition (Map)
* AChoir v0.28 - Add /MAP:  /USR:  and  /PWD:  command lines
* ............ - and MAP:  USR:  and  PWD:  INI file Actions
* ............ - to enable Mapping for Remote Acquisition
* AChoir v0.29 - Add ADM:Check and ADM:Force to check OR enforce that AChoir be run from an ADMIN ID
* ............ - Converted to MSVC 
* ............ - Also replaced libCurl with MS WinHTTP APIs
* AChoir v0.30 - Improve CPY: - Prevent Overwriting Files
* AChoir v0.31 - Start and End Time Stamps and &Tim variable
* AChoir v0.32 - Changes to support 32 and 64 Bit versions!
* AChoir v0.33 - New Option (USB:) Turn On/Off USB Write Protect
* AChoir v0.34 - Internal Code Cleanup
* AChoir v0.35 - Add DRV: Action to Set &Drv
* AChoir v0.36 - Add Variables 0-9 (VR0: - VR9:) (&VR0 - &VR9)
* ............ - Fix wierd Win7 "Application Data" Path
* ............ - Recursion Anomoly
* AChoir v0.37 - Remove DST Calculation - Add Checks to CPY:
* AChoir v0.38 - New DST Convergence Code
* AChoir v0.39 - Add LBL: and JMP: for Conditional Execution
* AChoir v0.40 - Add XIT: <Exit Command - Run on Exit>
* AChoir v0.41 - Add ARN:<Offline Registry File> Offline SOFTWARE Registry parse of Autorun programs 
* AChoir v0.44 - Fix root folder edge case
* AChoir v0.50 - Add CMD: - Like SYS: But uses a CMD.Exe shell, In &Dir - Check Hash for AChoir ReactOS Shell
* AChoir v0.55 - Add LST: - Looping Object (&LST) that reads entries from a file.  Also Add SID (file owner) copy on the CPY: command.
* AChoir v0.56 - Improve Privileges Message Display
* AChoir v0.57 - Fix Priv Bug & Add better Error Detection
* AChoir v0.75 - Add NTFS Raw Copy (NCP:)
* ............ - NCP:<Wilcard File Search> <Destination Dir>
* ............ - Additional Recursion Error Checking
* AChoir v0.80 - NTFS Raw Reading now support Attribute List
* ............ - (Multiple Cluster Runs/Fragmented Files)
* AChoir v0.81 - More NTFS Raw Read honing
* AChoir v0.82 - Add MAX: - Max File Size (& Mem Usage)
* AChoir v0.83 - Add RawCopy to ARN:
* AChoir v0.85 - Can now Read POSIX file names & Hard Links
* AChoir v0.89 - Large File (> 1GB) Support
* AChoir v0.90 - ADD HKCU Parsing for ARN:
* AChoir v0.91 - Edge case exit Bug Fix
* AChoir v0.92 - Sig:<Typ=xxxx> Load File Type, Hex Signature
* ............ - NCS: NTFS Copy by Signature
* ............ - (Used together to copy Files by Signature)
* AChoir v0.93 - Refactored some SQLite Code to avoid random
* ............ - Heap Corruption issues
* AChoir v0.95 - FINALLY Fix Abend Bug in Large File Support
* AChoir v0.96 - Clean Up some of the code, improve output.
* AChoir v0.96a- Cosmetic changes to Index.htm
* AChoir v0.97 - Add Colors, Minor Bug Fixes
* AChoir v0.98 - CPS: Copy by Signature (Standard Win32 API)
* ............ - (Used with SIG: to copy Files by Signature)
* ............ -  - Not Recommended for Locked/System Files 
* ............ - Tighten Application Data recursion to 2 lvls
* ............ - /Con or /ini:Console - Console as Input File
* AChoir v0.98a- Various improvements to Interactive Mode
* ............ - Replace conditional statements with messages
* ............ - add INI:Console to Scripting
* ............ - Improve switching between Script and Interactive Modes
* AChoir v1.0  - Cosmetic USB Message Changes
* ............ - HTTP Get Bug Fixes, Fix &Acq dblSlash
* ............ - Add Optional Case & Evidence Name/Number Input
* ............ - CSE:GET and CSE:SAY
* ............ - /CSE Argument to Get Case Information
* ............ - VCK:<x:\>  NTFS, FAT32, CDFS, Other, None
* ............ - &VCK - Contains Results of VCK:
* ............ - EQU:<s1> <s2> - Are S1 and S2 Equal?
* ............ - NEQ:<s1> <s2> - Are S1 and S2 NOT Equal?
* ............ - Support Indenting (spaces or Tabs)
* ............ - DSK:<type>  Set &DSK looping variable to
* ............ - Types: Removable, Fixed, Remote, CDROM
* ............ - &DSK - Looping Var Contains Disk that match 
* AChoir v1.1  - Peppered Flush STDOUT buffers for better
* ............ - PSExec Display (Remote Acq)
* ............ - SHR:<Path> <Name> - Create a Local Share
* ............ - SHD:<Name> - Delete a Local Share
* AChoir v1.2  - Add /USR:? and /PWD:? - Query MAP USR and PWD 
* ............ - Replaced getch() with getchar().  This is
* ............ - because PsExec does not work with getch().
* ............ - PsExec also does not work with SetConsoleMode
* ............ - so there is no way to do hidden/masked
* ............ - password input.
* AChoir v1.3  - Implement NTP Client for Querying Time Drift
* ............ - Fix minor display bug when using &Tim
* AChoir v1.4  - New Actions to Hide and Reconnect the Console
* ............ - CON:Hide and CON:Show
* ............ - SLP:<Sec> Sleep for <Sec>Seconds
* AChoir v1.5  - Add /VR0: -/VR9: Command Line Parameters
* ............ - When BaseDir changes, change Windows CWD too
* ............ - New Redaction Routine for PWD: EXE: CMD:
* AChoir v1.6  - Add EXA: and EXB:  (Asyn & Background EXe)
* AChoir v1.7  - Fix DSK: &DSK bug for Remote Collections 
* ............ - File not being properly closed causes loop.  
* AChoir v1.8  - Recognize Compressed Files, and allow them to 
* ............ -  be copied by the OS API to DeCompress them
* ............ -  The Flag for this behaviour is:  
* ............ -  SET:NCP=OSCOPY or SET:NCP=RAWONLY
* ............ - Also Added built in Support for WOW64 file 
* ............ -  redirection of X86 binCopy of SYSTEM32 
* ............ -  (sub) directories. This was needed for 
* ............ -  switching from rawcopy to bincopy - plus its 
* ............ -  a good general feature anyway.
* AChoir v1.9  - Recognize Compressed Size
* AChoir v1.9a - More Comressed Files Support
* AChoir v2.0  - Add LZNT1 Decompress Routine
* ............ - Flag behaviors have changed:  
* ............ -  SET:NCP=NODCMP - NoDecompression 
* ............ -  SET:NCP=DECOMP/RAWONLY - LZNT1 Decompress 
* ............ -  SET:NCP=OSCOPY - Do OS/API copy on Decomp Err
* AChoir v2.1  - Add App Compat Manifest - For 8.1 and above
* ............ -  comaptibility  
* ............ - Add new Conditional Logic on Windows Version  
* ............ - VER:WinXP, WinXP64, Vista, Win7, Win8, Win8.1 
* ............ -  Win10 
* ............ -  Win2000, Win2003, Win2008, Win2008R2,  
* ............ -  Win2012, Win2012R2, Win2016
* AChoir v2.2  - Add Ver: Client, and Server checks


# Quick Start (tl;dr):
The quickest way to get started with AChoir is to download the Achoir-Inst.exe 
file, run it, and allow it to build the default AChoir Toolkit.  

If you want to buid the toolkit onto an external USB drive, simply install Achoir 
to your external USB drive, and let the Install program run the build process 
from there.  Achoir will Install and build the toolkit onto the Drive and 
Directory it is installed to. This process also works if you want to install/run
AChoir from a network share.
