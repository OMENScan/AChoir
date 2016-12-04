@Echo Off
REM ***
REM * Change the following values in this batch file
REM * 1. \\<AChoir Server>\<AChoir Share> - The name of YOUR AChoir Server and Share
REM * 2. AChoirX.Acq - This is the default Remote AChoir Triage Script - You may want to change it
REM ***
CLS
Echo.
net use p: /del
net use p: \\<AChoir Server>\<AChoir Share>
if not exist p:\Achoir.exe goto :BadMap
p:
AChoir.exe /Ini:AChoirX.Acq
c:
net use p: /del
goto :AllDun
:BadMap
Echo.
Echo Could not Map to the AChoir Server...
Echo.
:AllDun
