# AChoir
Windows Live Artifacts Acquisition Scripting Framework

* AChoir v0.08 - Released as Open Source at my Live Acquisition presentation at BSides Las Vegas, August 2015
  * https://www.youtube.com/watch?v=NNPiSlVsA6M
* AChoir v0.09 - Added creation of Index.html for simple Artifact browsing
* AChoir v0.10 - Added Mapping to remote drives, and (re)setting the ACQDir
* AChoir v0.11 - Added &Map variable 
  * Added INI: action (switches the INI File) - Used for remote acquisition
  * Added INP: action and &Inp variable (Console Input and variable)


# Brief Description:
Every Incident Responder eventually comes to the conclusion that they need to script their favorite Live Acquisition utilities.  Many times those Live Acquisition scripts are shared only among trusted parties.

I have seen these scripts written in numerous scripting languages - but oddly enough, all of these scripts tend to use many of the same freely available utilities - To do mostly the same things.

It often takes an Incident Responder several years, along with lots of trial and error to settle on a set of utilities (and options) that both work and that provide relevant information on useful forensic artifacts.

And even though Responders often use the same utilities and are scripting them in largely the same way, each Responder has to go through the same pain of building their own script in their (not so) favorite scripting language - figuring out how to quickly and consistently gather the artifacts of most value. 

Achoir is a Framework/Scripting Tool to standardize and simplify that process.

# Quick Start (tl;dr):
The quickest way to get started with AChoir is to download the Achoir-Inst.exe file, run it, and allow it to build the default AChoir Toolkit.  

If you want to buid the toolkit onto an external USB drive, simply install Achoir to your external USB drive, and let the Install program run the build process from there.  Achoir will Install and build the toolkit onto the Drive and Directory it is installed to. 
