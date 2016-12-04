@Echo Off
REM ***
REM * Run AChoir on a Remote host by mapping to the AChoir Server
REM *
REM *  Note - %1 will be the name of the endpoint to Triage
REM *         This will be parsed by ACQRemote and passed to this 
REM *         .BAT file - These will come from:
REM *         1. The Triage: configuration option in ACQRemote.ini 
REM *         2. The JSON: configuration option in ACQRemote.ini 
REM *
REM *  Note - %1 %2 %3 etc... Are assigned via the ORDER of JSON:
REM *         configuration options
REM ***
net use \\%1\IPC$
if errorlevel 1 goto :BadMap
if errorlevel 0 goto :RunExec
goto :BadMap
:RunExec
REM *
REM * Below PSExec is used to upload and run the ACQ-R.bat on 
REM *  the endpoint to do the triage. 
REM *
C:\Web\Acq\Prog\psexec.exe \\%1 -h -c C:\Web\Acq\Prog\ACQ-R.bat -f
net use \\%1\IPC$ /del
goto :AllDun
:NoExec
Echo.
Echo * * * * * * * * * * * * * * * * * * * * * * * * * *
Echo *                                                 *
Echo * ERROR - PsExec could not be found!  Exiting.... *
Echo *                                                 *
Echo * * * * * * * * * * * * * * * * * * * * * * * * * *
goto :AllDun
:BadMap
Echo.
Echo * * * * * * * * * * * * * * * * * * * * * * * * * *
Echo *                                                 *
Echo * Bad UserID or Password.  Could not Connect.     *
Echo *                                                 *
Echo * * * * * * * * * * * * * * * * * * * * * * * * * *
goto :AllDun
:AllDun
