# AChoir
Windows Live Artifacts Acquisition Scripting Framework

AChoir has now been Converted to MSVC and Win HTTP. The original AChoir 
(Mingw and libcurl) will be left intact under AChoir-Legacy for those that 
prefer MingW.  However, all future development will be done to this fork.


* AChoir v0.08 - Released as Open Source at my Live Acquisition presentation 
  at BSides Las Vegas, August 2015
  * https://www.youtube.com/watch?v=NNPiSlVsA6M
* AChoir v0.09 - Added creation of Index.html for simple Artifact browsing
* AChoir v0.10 - Added Mapping to remote drives, and (re)setting the ACQDir
* AChoir v0.11 - Added &Map variable 
  * Added INI: action (switches the INI File) - Used for remote acquisition
  * Added INP: action and &Inp variable (Console Input and variable)
* AChoir v0.13 - New &Tmp is the Window %Temp% variable
  * New CPY: Action to copy files
  * New &FNM variable - Each &FOR File Name
* AChoir v0.20 - Lets call this 2.0-Lots of Code improvements
* AChoir v0.21 - Fix GMT DST idiosyncracy
* AChoir v0.22 - New ARN: Action - Parse the Run Key and copy the Autorun EXEs
* AChoir v0.23 - New /MNU Switch - Run the Menu.ACQ script
* AChoir v0.24 - Expand the ARN: routine to recognize WOW64
  * ...and System32/sysnative wierdness
* AChoir v0.25 - More improvements to Run Key Extract
* Achoir v0.25b - Add WinAudit and GPResult to Scripts
* AChoir v0.26 - Expand system variables %variable%
* AChoir v0.27 - More improvements in remote acquisition (Map)
* AChoir v0.28 - Add /MAP:  /USR:  and  /PWD:  command lines
  * and MAP:  USR:  and  PWD:  INI file Actions
  * to enable Mapping for Remote Acquisition
* AChoir v0.29 - Add ADM:Check and ADM:Force to check OR enforce that AChoir be run from an ADMIN ID
  - Converted to MSVC 
  - Also replaced libCurl with MS WinHTTP APIs
* AChoir v0.30 - Improve CPY: - Prevent Overwriting Files
* AChoir v0.31 - Start and End Time Stamps and &Tim variable
* AChoir v0.32 - Changes to support 32 and 64 Bit versions!
* AChoir v0.33 - New Option (USB:) Turn On/Off USB Write Protect
* AChoir v0.34 - Internal Code Cleanup


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

# Quick Start (tl;dr):
The quickest way to get started with AChoir is to download the Achoir-Inst.exe 
file, run it, and allow it to build the default AChoir Toolkit.  

If you want to buid the toolkit onto an external USB drive, simply install Achoir 
to your external USB drive, and let the Install program run the build process 
from there.  Achoir will Install and build the toolkit onto the Drive and 
Directory it is installed to. This process also works if you want to install/run
AChoir from a network share.
