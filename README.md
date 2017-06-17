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
* ............    and System32/sysnative wierdness
* AChoir v0.25 - More improvements to Run Key Extract
* Achoir v0.25b - Add WinAudit and GPResult to Scripts
* AChoir v0.26 - Expand system variables %variable%
* AChoir v0.27 - More improvements in remote acquisition (Map)
* AChoir v0.28 - Add /MAP:  /USR:  and  /PWD:  command lines
* ............   and MAP:  USR:  and  PWD:  INI file Actions
* ............   to enable Mapping for Remote Acquisition
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
* ............   Recursion Anomoly
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
* ............   (Used together to copy Files by Signature)
* AChoir v0.93 - Refactored some SQLite Code to avoid random
* ............   Heap Corruption issues
* AChoir v0.95 - FINALLY Fix Abend Bug in Large File Support
* AChoir v0.96 - Clean Up some of the code, improve output.
* AChoir v0.96a- Cosmetic changes to Index.htm
* AChoir v0.97 - Add Colors, Minor Bug Fixes
* AChoir v0.98 - CPS: Copy by Signature (Standard Win32 API)
* ............   (Used with SIG: to copy Files by Signature)
* ............    - Not Recommended for Locked/System Files 
* ............ - Tighten Application Data recursion to 2 lvls
* ............ - /Con or /ini:Console - Console as Input File
* AChoir v0.98a- Various improvements to Interactive Mode
* ............   - Replace conditional statements with messages
* ............   - add INI:Console to Scripting
* ............   - Improve switching between Script and Interactive Modes
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
* ............   - Types: Removable, Fixed, Remote, CDROM
* ............ - &DSK - Looping Var Contains Disk that match 


# Quick Start (tl;dr):
The quickest way to get started with AChoir is to download the Achoir-Inst.exe 
file, run it, and allow it to build the default AChoir Toolkit.  

If you want to buid the toolkit onto an external USB drive, simply install Achoir 
to your external USB drive, and let the Install program run the build process 
from there.  Achoir will Install and build the toolkit onto the Drive and 
Directory it is installed to. This process also works if you want to install/run
AChoir from a network share.
