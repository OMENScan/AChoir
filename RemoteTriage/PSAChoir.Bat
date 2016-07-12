REM ***
REM * Run AChoir on a Remote host by mapping to the AChoir Server
REM ***
CLS
@Echo Off
Echo.
Echo This script will Run AChoir on a Remote Host.
Echo.
if not exist psexec.exe goto :NoExec
Echo You will need:
Echo.
Echo 1. The Host Name of the machine you want to Triage
Echo.
Echo 2. Your Administrator/Examiner UserID (Include the Domain)
Echo     For Example: Domain-Name\UserID
Echo.
Echo 3. The Name of the AChoir Server Share
Echo     For Example: \\Server-Name\Share-Name
Echo.
set /p ACQHost="1. Enter the Computer Name to Triage: "
set /p ACQAdmin="2. Enter Your Administrator/Examiner UserID: "
set /p ACQServ="3. Enter the Host\Share Name of the AChoir Server Share: "
REM ***
REM * Write out the ACQX Batch File
REM ***
Echo @Echo Off > acqx.bat
Echo CLS >> acqx.bat
Echo Echo. >> acqx.bat
Echo net use p: /del >> acqx.bat
Echo net use p: %ACQServ% >> acqx.bat
Echo if not exist p:\Achoir.exe goto :BadMap >> acqx.bat
Echo p: >> acqx.bat
Echo AChoir.exe /Ini:AchoirX.Acq >> acqx.bat
Echo c: >> acqx.bat
Echo net use p: /del >> acqx.bat
Echo goto :AllDun >> acqx.bat
Echo :BadMap >> acqx.bat
Echo Echo. >> acqx.bat
Echo Echo Could not Map to the AChoir Server... >> acqx.bat
Echo Echo. >> acqx.bat
Echo :AllDun >> acqx.bat
psexec \\%ACQHost% -h -u %ACQAdmin% -c acqx.bat -f
Del Acqx.bat
goto :AllDun
:NoExec
Echo * * * * * * * * * * * * * * * * * * * * * * * * *
Echo *                                               *
Echo *     ERROR: PsExec not found in directory.     *
Echo *                                               *
Echo * * * * * * * * * * * * * * * * * * * * * * * * *
:AllDun
