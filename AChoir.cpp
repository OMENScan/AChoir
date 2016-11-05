/****************************************************************/
/* "As we benefit from the inventions of others, we should be   */
/*  glad to share our own...freely and gladly."                 */
/*                                          - Benjamin Franklin */
/*                                                              */
/* AChoir v0.01 - First Version  (D0n Quix0te 05/30/15)         */
/* AChoir v0.02 - Add Variables: &Dir &Fil &Acq &Win            */
/* AChoir v0.03 - Add Hashing                                   */
/* AChoir v0.04 - Add FOR:, &FOR, &NUM  Looping                 */
/* AChoir v0.05 - Add CKY:, CKN:, RC=:, RC!:, RC>:, RC<:, END:  */
/*                &CHK, &RCD                                    */
/* AChoir v0.06 - Add Logging                                   */
/* AChoir v0.07 - Add /BLD (Build.Acq), /DRV:, &Prc, 32B:, 64B: */
/*                BYE:                                          */
/* AChoir v0.08 - Hash Program before running,Set Artifacts ROS */
/* AChoir v0.09 - Create Index.html for Artifact Browsing       */
/* AChoir v0.10 - Mapping External Drives - Set to the ACQDir   */
/* AChoir v0.11 - New &Map variable and INI: action             */
/*                INP: action and &Inp variable (Console Input) */
/* AChoir v0.13 - New &Tmp is the Window %Temp% variable        */
/*                New CPY: Action to copy files                 */
/*                New &FNM variable - Each &FOR File Name       */
/* AChoir v0.20 - Lets call this 2.0-Lots of Code improvements  */
/* AChoir v0.21 - Fix GMT DST idiosyncracy                      */
/* AChoir v0.22 - New ARN: Action -                             */
/*                Parse the Run Key and copy the Autorun EXEs   */
/* AChoir v0.23 - /MNU Command Line Option Runs Menu.ACQ        */
/* AChoir v0.24 - Expand the ARN: routine to recognize WOW64    */
/*                and System32/sysnative wierdness              */
/* AChoir v0.25 - More improvements to Run Key Extract          */
/* AChoir v0.26 - Expand system variables %variable%            */
/* AChoir v0.27 - More improvements in remote acquisition (Map) */
/* AChoir v0.28 - Add /MAP:  /USR:  and  /PWD:  command lines   */
/*                and MAP:  USR:  and  PWD:  INI file Actions   */
/*                to enable Mapping for Remote Acquisition      */
/* AChoir v0.29 - Add ADM:Check and ADM:Force to check OR       */
/*                enforce that AChoir be run from an ADMIN ID   */
/*              - Converted to MSVC - Also replaced libCurl     */
/*                with MS WinHTTP APIs                          */
/* AChoir v0.30 - Improve CPY: - Prevent Overwriting Files      */
/* AChoir v0.31 - Start and End Time Stamps and &Tim variable   */
/* AChoir v0.32 - Changes to support 32 and 64 Bit versions!    */
/* AChoir v0.33 - Turn On/Off USB Write Protect                 */
/* AChoir v0.34 - Internal Code Cleanup                         */
/* AChoir v0.35 - Add DRV: Action to Set &Drv                   */
/* AChoir v0.36 - Add Variables 0-9 (VR0: - VR9:) (&VR0 - &VR9) */
/*              - Fix wierd Win7 "Application Data" Path        */
/*                 Recursion Anomoly                            */
/* AChoir v0.37 - Remove DST Calculation - Add Checks to CPY:   */
/* AChoir v0.38 - New DST Convergence Code                      */
/* AChoir v0.39 - Add LBL: and JMP: for Conditional Execution   */
/* AChoir v0.40 - Add XIT: <Exit Command - Run on Exit>         */
/* AChoir v0.41 - Offline Registry parse of AutoRun Keys        */
/*                for DeadBox analysis                          */
/* AChoir v0.42 - Change HTML display to only Root Folder       */
/* AChoir v0.43 - Match DLL Delay Loading to &Dir Directory     */
/* AChoir v0.44 - Fix root folder edge case                     */
/* AChoir v0.50 - Add CMD: - Like SYS: But uses a CMD.Exe shell */
/*                In &Dir - Check Hash for AChoir ReactOS Shell */
/* AChoir v0.55 - Add LST: - Looping Object (&LST) that reads   */
/*                 entries from a file.  Also Add SID (file     */
/*                 owner) copy on the CPY: command.             */
/* AChoir v0.56 - Improve Privileges Message Display            */
/* AChoir v0.57 - Fix Priv Bug & Add better Error Detection     */
/* AChoir v0.75 - Add NTFS Raw Copy (NCP:)                      */
/*                NCP:<Wilcard File Search> <Destination Dir>   */
/*              - Additional Recursion Error Checking           */
/* AChoir v0.80 - NTFS Raw Reading now support Attribute List   */
/*                (Multiple Cluster Runs/Fragmented Files)      */
/* AChoir v0.81 - More NTFS Raw Read honing                     */
/* AChoir v0.82 - Add MAX: - Max File Size (& Mem Usage)        */
/* AChoir v0.83 - Add RawCopy to ARN:                           */
/* AChoir v0.85 - Can now Read POSIX file names & Hard Links    */
/*                                                              */
/*  rc=0 - All Good                                             */
/*  rc=1 - Bad Input                                            */
/*  rc=2 - Bad Execution                                        */
/*  rc=3 - Internal Error                                       */
/*                                                              */
/****************************************************************/

/****************************************************************/
/* IMPORTANT NOTE : I could not have implemented the NTFS       */
/* Raw Copy function without the Excellent NTFS tutorial at:    */
/* http ://www.installsetupconfig.com/win32programming/         */
/*         windowsvolumeapis1index.html                         */
/*                                                              */
/* Much of the code in the Achoir NTFS Raw Copy function is     */
/* directly from this tutorial.And I want to publicly thank     */
/*   them for making this example code available.               */
/****************************************************************/

#include "stdafx.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/* #ifndef NO_UNISTD
   #include <unistd.h>
   #endif NO_UNISTD 
*/

#include <conio.h>
#include <time.h>
#include <io.h>
#include <direct.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <process.h>

#include <windows.h>
#include <winbase.h>

#include "md5.h"

#include <winhttp.h>
#include <Winnetwk.h>
#include <Offreg.h>

#include "ntfs.h"
#include "sqlite3.h"

// #pragma comment (lib, "offreg.lib")
// #pragma comment(lib, "cmcfg32.lib")
#pragma comment(lib, "Advapi32.lib")

#include "accctrl.h"
#include "aclapi.h"
#include <sddl.h>

#define NUL '\0'
#define MaxArray 100
#define BUFSIZE 4096

char Version[10] = "v0.85\0";
char RunMode[10] = "Run\0";
int  iRanMode = 0;
int  iRunMode = 0;
int  iHtmMode = 0;
int  iChkYN = 0;
int  iChkRC = 0;
int  iIsAdmin = 0;

char ACQName[255];
char ACQDir[1024];
char BACQDir[1024];
char CachDir[1024];

char buffer[BUFSIZE];
char filename[FILENAME_MAX];

int verboseflag = 0;
int DebugFlag = 0;

int ListDir(char *DirName, char *LisType);
size_t Squish(char *SqString);
long twoSplit(char *SpString);
char *stristr(const char *String, const char *Pattern);
int  FileMD5(char *MD5FileName);
int  MemAllocErr(char *ErrType);
int  binCopy(char *FrmFile, char *TooFile, int binLog);
void Time_tToFileTime(time_t InTimeT, int whichTime);
long varConvert(char *inVarRec);
long consInput(char *consString, int conLog);
long mapsDrive(char *mapString, int mapLog);
int PreIndex();
BOOL IsUserAdmin(VOID);
void showTime(char *showText);
void USB_Protect(DWORD USBOnOff);
int  cleanUp_Exit(int exitRC);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
char * convert_sid_to_string_sid(const PSID psid, char *sid_str);

// Routines For Raw NTFS Access
ULONG RunLength(PUCHAR run);
LONGLONG RunLCN(PUCHAR run);
ULONGLONG RunCount(PUCHAR run);
BOOL FindRun(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, PULONGLONG lcn, PULONGLONG count);
PATTRIBUTE FindAttribute(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, PWSTR name);
PATTRIBUTE FindAttributeX(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, PWSTR name, int attrNum);
VOID FixupUpdateSequenceArray(PFILE_RECORD_HEADER file);
VOID ReadSector(ULONGLONG sector, ULONG count, PVOID buffer);
VOID ReadLCN(ULONGLONG lcn, ULONG count, PVOID buffer);
VOID ReadExternalAttribute(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, ULONG count, PVOID buffer);
ULONG AttributeLength(PATTRIBUTE attr);
ULONG AttributeLengthAllocated(PATTRIBUTE attr);
ULONG AttributeLengthDataSize(PATTRIBUTE attr);
VOID ReadAttribute(PATTRIBUTE attr, PVOID buffer);
VOID ReadVCN(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, ULONGLONG vcn, ULONG count, PVOID buffer);
VOID ReadFileRecord(ULONG index, PFILE_RECORD_HEADER file);
VOID LoadMFT();
VOID UnloadMFT();
VOID FindActive();
int rawCopy(char *FrmFile, char *TooFile, int binLog);
int DumpDataII(ULONG index, CHAR* filename, CHAR* outdir, FILETIME ToCreTime, FILETIME ToModTime, FILETIME ToAccTime, int binLog, int Append);


// Global Variables For Raw NTFS Access
ULONG BytesPerFileRecord;
HANDLE hVolume;
BOOT_BLOCK bootb;
PFILE_RECORD_HEADER MFT;
int readRetcd = 1; // Global read Return Code - When something goes real bad.
char Str_Temp[1024] = "\0";
CHAR driveLetter[] = "C\0\0\0\0";
CHAR rootDrive[] = "C:\\\0\0\0";

int gotOwner = 0;
PSECURITY_DESCRIPTOR SecDesc = NULL;
ULONG maxMemBytes = 999999999; //Max Memory Alloc = 1Gb


// Global Variables For SQLite Databases
int SpinLock;
int MFT_Status = 0; // 0=Good, 1=NonFatal Error, 2=FatalError
char *dbMQuery; char *errmsg = 0; int dbMrc;
char *dbXQuery; int dbXrc; int dbXi;
int  dbrc, dbMaxCol, dbRowCount, dbi;
char MFTDBFile[1024] = "C:\\AChoir\\Cache\\C-MFT.db\0";
sqlite3      *dbMFTHndl;
sqlite3_stmt *dbMFTStmt;
sqlite3_stmt *dbXMFTStmt;

FILE* LogHndl;
FILE* CpyHndl;
FILE* ForHndl;
FILE* LstHndl;
FILE* MD5Hndl;
FILE* IniHndl;
FILE* WGetHndl;
FILE* HtmHndl;

char LogFile[1024] = "C:\\AChoir\\AChoir.exe\0";
char CpyFile[1024] = "C:\\AChoir\\AChoir.exe\0";
char ChkFile[1024] = "C:\\AChoir\\AChoir.exe\0";
char MD5File[1024] = "C:\\AChoir\\Hashes.txt\0";
char ForFile[1024] = "C:\\AChoir\\ForFiles\0";
char LstFile[1024] = "C:\\AChoir\\LstFiles\0";
char IniFile[1024] = "C:\\AChoir\\AChoir.ACQ\0";
char HtmFile[1024] = "C:\\AChoir\\Index.html\0";
char CmdExe[1024] = "C:\\AChoir\\cmd.exe\0";
char CmdHash[35] = "d05c529f0eebb6aaf10cbdecde14d310\0";
char TempDir[1024] = "C:\\AChoir\0";
char BaseDir[1024] = "C:\\AChoir\0";
char CurrDir[1024] = "\0";
char CurrFil[255] = "AChoir.dat\0";
char DiskDrive[10] = "C:\0\0\0";
char MapDrive[10] = "C:\0\0\0";
char *WinRoot = "C:\\Windows";
char *Procesr = "AMD64";
char *TempVar = "C:\\Windows\\Temp";
char *ProgVar = "C:\\Program Files";

HANDLE SecTokn;
int PrivSet = 0;
int PrivOwn = 0;
int PrivSec = 0;
int PrivBac = 0;
int PrivRes = 0;

int  WGetIni, WGetIsGood, WGotIsGood;
size_t  lastChar;

char *iWGetFIL;
char WGetFile[1024] = "C:\\AChoir\\Achoir.dat\0";
char WGetURL[1024] = "http://127.0.0.1/AChoir/AChoir.dat\0";
char WGetDOM[1024] = "http://127.0.0.1";
char WGetFIL[1024] = "/AChoir/AChoir.dat\0";

wchar_t w_WGetURL[2028];
wchar_t w_WGetFIL[2028];
LPWSTR lpWGetURL = w_WGetURL;
LPWSTR lpWGetFIL = w_WGetFIL;

char FileRoot[1024] = "C:\\InetPub\\wwwroot\0";
char FullRoot[1024] = "C:\\InetPub\\wwwroot\0";

char LastRec[2048];
char ThisRec[2048];
char cpyChar;

int  iVar;
char VarArray[2560]; // Ten 256 Byte Variables (&Var0 - &Var9)

int  iMonth, iDay, iYear, iHour, iMin, iSec, iYYYY;

time_t timeval;
struct tm *lclTime;
char FullDateTime[25] = "01/01/0001 - 01:01:01\0";
char OldDate[30] = "\0";
struct tm *Old_CTime;
struct tm *Old_MTime;
struct tm *Old_ATime;

char MD5In1[256] = "\0";
char MD5In2[256] = "\0";
char MD5Out[256] = "\0";
char MD5Tmp[256] = "\0";

int  iNeedSize;
int  iLeftSize;
char *recvData;
char *recvTemp;
int  recvSize = 25000;

int  LastRC = 0;
int  ChkRC = 0;
char *ExePtr, *ParmPtr, *CopyPtr;


char RootDir[FILENAME_MAX] = " \0";
char FullFName[FILENAME_MAX];
char ForFName[FILENAME_MAX];

DWORD netRC = NO_ERROR;
NETRESOURCE netRes = { 0 };
TCHAR szConnection[MAX_PATH];
DWORD ConnectSize = MAX_PATH, ConnectResult, Flags = (CONNECT_INTERACTIVE | CONNECT_REDIRECT);

size_t iPrm1, iPrm2, iPrm3;
char *iPtr1, *iPtr2, *iPtr3;

struct stat Frmstat;
struct stat Toostat;
FILETIME TmpTime;
FILETIME ToCTime;
FILETIME ToMTime;
FILETIME ToATime;
LPFILETIME OutFileTime;

LPCTSTR lpSubKey = TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\0");

DWORD rcDword;
DWORD nSubkeys;
DWORD nValues;
PCWSTR ORlpSubKey = L"Microsoft\\Windows\\CurrentVersion\\Run\0";
PCWSTR ORlp6432 = L"Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\0";

char    WDLLPath[256];

DWORD ulOptions = 0;
REGSAM samWOW64 = KEY_READ | KEY_WOW64_64KEY;
REGSAM samWOW32 = KEY_READ | KEY_WOW64_32KEY;
REGSAM samDesired = KEY_READ;

long OpenK;
long OpenRC;
long ReadK;
long MakeK;

HKEY  hKey = HKEY_LOCAL_MACHINE;
ORHKEY ORhKey = HKEY_LOCAL_MACHINE;

HKEY   phkResult;
ORHKEY ORphkResult;

size_t sizeofChars = 0;
size_t convertedChars = 0;
wchar_t w_ORFName[2028];
LPWSTR lpORFName = w_ORFName;

DWORD  dwIndex = 0;
TCHAR  lpValueName[2048];
DWORD  lpcchValueName = 2048;
LPTSTR lpData[2048];
DWORD  lpcbData = 2048;

wchar_t  w_lpValueName[2048];
PWSTR ORlpValueName = w_lpValueName;

int  samLoop = 0;
char o32VarRec[4096];
char o64VarRec[4096];
int  i64x32;

char Inrec[4096];
char Inprec[255];
char Conrec[255];
char inUser[255];
char inPass[255];
char inMapp[255];
char inFnam[255];
char JmpLbl[255];
int  iGoodMap = 0;
int  iArgsMap = 0;
int  getKey;

int  iXitCmd = 0;
char XitCmd[4096];

//Track Current File Information across Routines
int fileIsFrag;
ULONG totbytes, totdata;
ULONG maxFileSize, leftFileSize;
ULONG maxDataSize, leftDataSize;
int LCNType = 0;  // 0 for Attributes, 1 for Files (used for tracking leftFileSize)
int iDepth = 0;   // Sanity Check for Recursion Loops

// Template for padding
template <class T1, class T2> inline T1* Padd(T1* p, T2 n)
{
  return (T1*)((char *)p + n);
}

int main(int argc, char *argv[])
{
  int i;
  int iPtr;
  size_t oPtr, ArnLen, ArnPtr;
  int RunMe, ForMe, LstMe, Looper, LoopNum;

  char Tmprec[2048];
  char Filrec[2048];
  char Lstrec[2048];
  char Cpyrec[4096];
  char Exerec[4096];
  char Arnrec[2048];

  DWORD dwSize = 0;
  DWORD dwDownloaded = 0;
  LPSTR pszOutBuffer;
  BOOL bResults = FALSE;
  HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    
  char *ForSlash;
  char *RootSlash;

  char cName[MAX_COMPUTERNAME_LENGTH + 1];
  DWORD len = 55;

  char * pointEnd;

  time(&timeval);
  lclTime = localtime(&timeval);
  iMonth = lclTime->tm_mon + 1;
  iDay = lclTime->tm_mday;
  iYYYY = lclTime->tm_year + 1900;
  iYear = iYYYY - 2000;
  iHour = lclTime->tm_hour;
  iMin = lclTime->tm_min;
  iSec = lclTime->tm_sec;


  /****************************************************************/
  /* Volume Information Variables                                 */
  /****************************************************************/
  TCHAR volumeName[MAX_PATH + 1] = { 0 };
  TCHAR fileSystemName[MAX_PATH + 1] = { 0 };
  DWORD serialNumber = 0;
  DWORD maxComponentLen = 0;
  DWORD fileSystemFlags = 0;
  int isNTFS = 0;


  /****************************************************************/
  /* Set Defaults                                                 */
  /****************************************************************/
  iIsAdmin = 0;
  iXitCmd = 0;

  memset(CurrDir, 0, 1024);
  memset(TempDir, 0, 1024);
  memset(BaseDir, 0, 1024);
  memset(BACQDir, 0, 1024);
  memset(CachDir, 0, 1024);
  memset(Inprec, 0, 255);
  memset(Conrec, 0, 255);
  memset(inFnam, 0, 255);
  memset(inMapp, 0, 255);
  memset(inUser, 0, 255);
  memset(inPass, 0, 255);

  memset(VarArray, 0, 2560);

  strncpy(inFnam, "AChoir.ACQ\0", 11);


  /****************************************************************/
  /* What Directory are we in?                                    */
  /****************************************************************/
  getcwd(BaseDir, 1000);


  /****************************************************************/
  /* Remove any Trailing Slashes.  This happens if CWD is a       */
  /*  mapped network drive (since it is at the root directory)    */
  /****************************************************************/
  lastChar = strlen(BaseDir);
  if ((BaseDir[lastChar-1] == '\\') && (lastChar > 2))
    BaseDir[lastChar-1] = '\0';


  /****************************************************************/
  /* Get Envars                                                   */
  /****************************************************************/
  WinRoot = getenv("systemroot");
  Procesr = getenv("processor_architecture");
  TempVar = getenv("temp");
  ProgVar = getenv("programfiles");


  /****************************************************************/
  /* Setup The initial 64Bit or 32Bit DLL Loading Directory       */
  /****************************************************************/
  memset(WDLLPath, 0, 256);

  if (strnicmp(Procesr, "AMD64", 5) == 0)
    sprintf(WDLLPath, "%s\\64Bit\0", BaseDir);
  else
    sprintf(WDLLPath, "%s\\32Bit\0", BaseDir);

  SetDllDirectory((LPCSTR)WDLLPath);


  /****************************************************************/
  /* Build the &ACQ Incident Number                               */
  /****************************************************************/
  if (GetComputerName(cName, &len) != 0)
    sprintf(ACQName, "ACQ-IR-%s-%04d%02d%02d-%02d%02d\0", cName, iYYYY, iMonth, iDay, iHour, iMin);
  else
    sprintf(ACQName, "ACQ-IR-%04d%02d%02d-%02d%02d\0", iYYYY, iMonth, iDay, iHour, iMin);

  
  /****************************************************************/
  /* Get the Runmode: (Default == 1)                              */
  /*  BLD = Go Get the Utilities via cURL                         */
  /*  MNU = Run the Menu.ACQ - a VERY simple menu script          */
  /*  RUN = Run the Live Acquisition Utility Script               */
  /*                                                              */
  /****************************************************************/
  iRunMode = 1;
  iArgsMap = 0;
  for (i = 1; i<argc; i++)
  {
    if ((strnicmp(argv[i], "/Help", 5) == 0) && (strlen(argv[i]) < 255))
    {
      printf("AChoir Arguments:\n\n");
      printf(" /HELP - This Description\n");
      printf(" /BLD  - Run the Build.ACQ Script (Build the AChoir Toolkit)\n");
      printf(" /MNU  - Run the Menu.ACQ Script (A Simple AChoir Menu)\n");
      printf(" /RUN  - Run the AChoir.ACQ Script to do a Live Acquisition\n");
      printf(" /DRV:<x:> - Set the &DRV parameter\n");
      printf(" /USR:<UserID> - User to Map to Remote Server\n");
      printf(" /PWD:<Password> - Password to Map to Remote Server\n");
      printf(" /MAP:<Server\\Share> - Map to a Remote Server\n");
      printf(" /INI:<File Name> - Run the <File Name> script instead of AChoir.ACQ\n");
      
      exit(0);
    }
    else
    if ((strnicmp(argv[i], "/BLD", 4) == 0) && (strlen(argv[i]) == 4))
    {
      strncpy(RunMode, "Bld\0", 4);
      strncpy(inFnam, "Build.ACQ\0", 10);
      iRunMode = 0;
    }
    else
    if ((strnicmp(argv[i], "/RUN", 4) == 0) && (strlen(argv[i]) == 4))
    {
      strncpy(RunMode, "Run\0", 4);
      strncpy(inFnam, "AChoir.ACQ\0", 11);
      iRunMode = 1;
    }
    else
    if ((strnicmp(argv[i], "/MNU", 4) == 0) && (strlen(argv[i]) == 4))
    {
      strncpy(RunMode, "Mnu\0", 4);
      strncpy(inFnam, "Menu.ACQ\0", 10);
      iRunMode = 3;
    }
    else
    if (strnicmp(argv[i], "/DRV:", 4) == 0)
    {
      if ((argv[i][6] == ':') && (strlen(argv[i]) == 7))
      {
        strncpy(DiskDrive, argv[i] + 5, 2);
        printf("Set: Disk Drive Set: %s\n", DiskDrive);
      }
      else
       printf("Err: Invalid Disk Drive Setting: %s\n", argv[i] + 5);

    }
    else
    if ((strnicmp(argv[i], "/INI:", 5) == 0) && (strlen(argv[i]) > 5))
    {
      if (strlen(argv[i]) < 254)
      {
        strncpy(RunMode, "Ini\0", 4);
        strncpy(inFnam, argv[i] + 5, 254);
        iRunMode = 2;
      }
      else
        printf("Err: /INI:  Too Long (Greater than 254 chars)\n");
    }
    else
    if (strnicmp(argv[i], "/MAP:", 5) == 0)
    {
      if (strlen(argv[i]) < 254)
      {
        iArgsMap = 1;
        memset(inMapp, 0, 255);
        strncpy(inMapp, argv[i] + 5, 254);
      }
      else
        printf("Err: /MAP:  Too Long (Greater than 254 chars)\n");
    }
    else
    if (strnicmp(argv[i], "/USR:", 5) == 0)
    {
      if (strlen(argv[i]) < 254)
      {
        memset(inUser, 0, 255);
        strncpy(inUser, argv[i] + 5, 254);
      }
      else
        printf("Err: /USR:  Too Long (Greater than 254 chars)\n");
    }
    else
    if (strnicmp(argv[i], "/PWD:", 5) == 0)
    {
      if (strlen(argv[i]) < 254)
      {
        memset(inPass, 0, 255);
        strncpy(inPass, argv[i] + 5, 254);
      }
      else
        printf("Err: /PWD:  Too Long (Greater than 254 chars)\n");
    }
    else
    {
      printf("Err: Bad Argument: %s\n", argv[i]);
    }
  }


  /****************************************************************/
  /* Should we Map a Drive First?  If yes, set the BaseDir and    */
  /*  DLL Directory too.                                          */
  /****************************************************************/
  if (iArgsMap == 1)
  {
    mapsDrive(inMapp, 0);
    strncpy(BaseDir, MapDrive, 4);

    memset(WDLLPath, 0, 256);

    if (strnicmp(Procesr, "AMD64", 5) == 0)
      sprintf(WDLLPath, "%s\\64Bit\0", BaseDir);
    else
      sprintf(WDLLPath, "%s\\32Bit\0", BaseDir);

    SetDllDirectory((LPCSTR)WDLLPath);
  }



  /****************************************************************/
  /* Set Initial File Names (BaseDir needs to be set 1st)         */
  /****************************************************************/
  sprintf(IniFile, "%s\\%s\0", BaseDir, inFnam);
  sprintf(WGetFile, "%s\\AChoir.Dat\0", BaseDir);
  //sprintf(ForFile, "%s\\ForFiles\0", BaseDir);
  sprintf(ForFile, "%s\\%s\\Cache\\ForFiles\0", BaseDir, ACQName);
  sprintf(LstFile, "%s\\LstFiles\0", BaseDir);
  sprintf(ChkFile, "%s\\AChoir.exe\0", BaseDir);
  sprintf(BACQDir, "%s\\%s\0", BaseDir, ACQName);
  sprintf(CachDir, "%s\\%s\\Cache\0", BaseDir, ACQName);



  /****************************************************************/
  /* Create Log Dir if it aint there                              */
  /****************************************************************/
  sprintf(LogFile, "%s\\Logs\0", BaseDir);
  if (access(LogFile, 0) != 0)
    mkdir(LogFile);


  /****************************************************************/
  /* Logging!                                                     */
  /****************************************************************/
  sprintf(LogFile, "%s\\Logs\\ACQ-IR-%04d%02d%02d-%02d%02d.Log\0", BaseDir, iYYYY, iMonth, iDay, iHour, iMin);
  LogHndl = fopen(LogFile, "w");
  if (LogHndl == NULL)
  {
    printf("Err: Could not Open Log File.\n");
    exit(3);
  }


  printf("Inf: AChoir ver: %s, Mode: %s\n", Version, RunMode);
  fprintf(LogHndl, "Inf: AChoir ver: %s, Mode: %s\n", Version, RunMode);

  showTime("Start Acquisition");

  /****************************************************************/
  /* Check If We are an Admin                                     */
  /****************************************************************/
  if (IsUserAdmin() == TRUE)
  {
    iIsAdmin = 1;
    printf("Inf: Running As Admin\n");
    fprintf(LogHndl, "Inf: Running As Admin\n");
  }
  else
  {
    printf("Inf: Running As NON-Admin\n");
    fprintf(LogHndl, "Inf: Running As NON-Admin\n");
    iIsAdmin = 0;
  }


  /****************************************************************/
  /* Get Basic Security Priveleges we will need before starting   */
  /****************************************************************/
  PrivSet = PrivOwn = PrivSec = PrivBac = PrivRes = 0;

  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &SecTokn))
  {
    if (SetPrivilege(SecTokn, "SeTakeOwnershipPrivilege", 1))
      PrivOwn = 1;

    if (SetPrivilege(SecTokn, "SeSecurityPrivilege", 1))
      PrivSec = 1;

    if (SetPrivilege(SecTokn, "SeBackupPrivilege", 1))
      PrivBac = 1;

    if (SetPrivilege(SecTokn, "SeRestorePrivilege", 1))
      PrivRes = 1;

    PrivSet = PrivOwn + PrivSec + PrivBac + PrivRes;
  }

  printf("Inf: Privileges(%d):", PrivSet);
  fprintf(LogHndl, "Inf: Privileges(%d):", PrivSet);

  if (PrivSet == 0)
  {
    printf(" None");
    fprintf(LogHndl, " None");
  }
  else
  {
    if (PrivOwn == 1)
    {
      printf(" TakeOwnership");
      fprintf(LogHndl, " TakeOwnership");
    }

    if (PrivSec == 1)
    {
      printf(" Security");
      fprintf(LogHndl, " Security");
    }

    if (PrivBac == 1)
    {
      printf(" Backup");
      fprintf(LogHndl, " Backup");
    }

    if (PrivRes == 1)
    {
      printf(" Restore");
      fprintf(LogHndl, " Restore");
    }
  }

  printf("\n\n");
  fprintf(LogHndl, "\n\n");

  fprintf(LogHndl, "Inf: Directory Has Been Set To: %s\\%s\n", BaseDir, CurrDir);
  fprintf(LogHndl, "Set: Input Script Set:\n     %s\n\n", IniFile);


  /****************************************************************/
  /* If iRunMode=1 Create the BACQDir - Base Acquisition Dir      */
  /****************************************************************/
  if (iRunMode == 1)
  {
    // Have we created the Base Acquisition Directory Yet?
    fprintf(LogHndl, "Set: Creating Base Acquisition Directory: %s\n", BACQDir);
    printf("Set: Creating Base Acquisition Directory: %s\n", BACQDir);

    if (access(BACQDir, 0) != 0)
    {
      mkdir(BACQDir);
      mkdir(CachDir);
      PreIndex();
    }
  }



  /****************************************************************/
  /* Open The Input Script File                                   */
  /****************************************************************/
  memset(Inrec, 0, 4096);
  memset(Tmprec, 0, 2048);

  IniHndl = fopen(IniFile, "r");

  if (IniHndl != NULL)
  {
    RunMe = 0;  // Conditional run Script default is yes

    while (fgets(Tmprec, 1000, IniHndl))
    {
      /****************************************************************/
      /* Conditional Execution                                        */
      /****************************************************************/
      if (RunMe > 0)
      {
        if (strnicmp(Tmprec, "32B:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "64B:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "CKY:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "CKN:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "RC=:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "RC!:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "RC>:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "RC<:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "END:", 4) == 0)
          RunMe--;
      }
      else
      {
        Looper = 1;

        /****************************************************************/
        /* ForFiles Looper Setup                                        */
        /****************************************************************/
        if (stristr(Tmprec, "&FOR") > 0)
        {
          ForMe = 1;
          memset(Filrec, 0, 2048);

          ForHndl = fopen(ForFile, "r");

          if (ForHndl == NULL)
          {
            fprintf(LogHndl, "Err: &FOR Directory has not been set.  Ignoring &FOR Loop...\n");
            printf("Err: &FOR Directory has not been set.  Ignoring &FOR Loop...\n");
            Looper = 0;
          }
        }
        else
          ForMe = 0;


        /****************************************************************/
        /* LstFiles Looper Setup                                        */
        /****************************************************************/
        if (stristr(Tmprec, "&LST") > 0)
        {
          LstMe = 1;
          memset(Lstrec, 0, 2048);

          LstHndl = fopen(LstFile, "r");

          if (LstHndl == NULL)
          {
            fprintf(LogHndl, "Err: &LST Directory not found: %s\n", LstFile);
            printf("Err: &LST Directory not found: %s\n", LstFile);
            Looper = 0;
          }
        }
        else
          LstMe = 0;
        

        /****************************************************************/
        /* Loop (FOR: and LST:) until Looper = 1                        */
        /****************************************************************/
        LoopNum = 0;
        while (Looper == 1)
        {
          if ((ForMe == 0) && (LstMe == 0))
            Looper = 0;
          else
          if ((ForMe == 1) && (LstMe == 0))
          {
            if (fgets(Filrec, 1000, ForHndl))
            {
              Looper = 1;
              LoopNum++;

              strtok(Filrec, "\n");
              strtok(Filrec, "\r");


              /****************************************************************/
              /* Get Just the File Name                                       */
              /****************************************************************/
              if ((ForSlash = strrchr(Filrec, '\\')) != NULL)
              {
                if (strlen(ForSlash + 1) > 1)
                  strncpy(ForFName, ForSlash + 1, 250);
                else
                  strncpy(ForFName, "Unknown\0", 8);
              }
              else
                strncpy(ForFName, Filrec, 250);
            }
            else
              break;
          }
          else
          if ((ForMe == 0) && (LstMe == 1))
          {
            if (fgets(Lstrec, 1000, LstHndl))
            {
              Looper = 1;
              LoopNum++;

              strtok(Filrec, "\n");
              strtok(Filrec, "\r");
            }
            else
              break;
          }
          else
          {
            Looper = 0;

            fprintf(LogHndl, "Err: AChoir does not yet support Nested Looping (&LST + &FOR)\n     > %s\n", Tmprec);
            printf("Err: AChoir does not yet support Nested Looping (&LST + &FOR)\n     > %s\n", Tmprec);

            strncpy(Tmprec, "***: Command Bypassed\0\0\0\0\0\0\0\0\0", 25);
          }
          
          
          /****************************************************************/
          /* Expand the record, replacing variables                       */
          /****************************************************************/
          Inrec[0] = '\0';
          oPtr = 0;


          /****************************************************************/
          /* Check for System (DOS/Win) Variables and Expand them         */
          /****************************************************************/
          varConvert(Tmprec);


          /****************************************************************/
          /* Now Further expand o32VarRec for Achoir unique variables     */
          /****************************************************************/
          for (iPtr = 0; iPtr < 2000; iPtr++)
          {
            if (strnicmp(o32VarRec + iPtr, "&Dir", 4) == 0)
            {
              if (strlen(CurrDir) > 0)
                sprintf(Inrec + oPtr, "%s\\%s", BaseDir, CurrDir);
              else
                sprintf(Inrec + oPtr, "%s", BaseDir);

              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Fil", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s", CurrFil);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Tim", 4) == 0)
            {
              // Full Date and Time - mm/dd/yyyy - hh:mm:ss
              memset(FullDateTime, 0, 25);
              showTime("&Tim");
                
              sprintf(Inrec + oPtr, "%s", FullDateTime);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Inp", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s", Inprec);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Acq", 4) == 0)
            {
              if (strlen(ACQDir) > 0)
                sprintf(Inrec + oPtr, "%s\\%s", BACQDir, ACQDir);
              else
                sprintf(Inrec + oPtr, "%s", BACQDir);

              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Win", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s", WinRoot);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Tmp", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s", TempVar);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&For", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s", Filrec);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Lst", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s", Lstrec);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Num", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%d\0", LoopNum);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Fnm", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s\0", ForFName);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Rcd", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%d\0", LastRC);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Chk", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s\0", ChkFile);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Drv", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s\0", DiskDrive);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Map", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s\0", MapDrive);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&Prc", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s\0", Procesr);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if ((o32VarRec[iPtr] == '*') && (strnicmp(o32VarRec, "NCP:", 4) == 0))
            {
              //Special Case to replace WildCard for NCP: with SQLite Wildcards (%)
              sprintf(Inrec + oPtr, "%%\0");
              oPtr = strlen(Inrec);
            }
            else
            if ((o32VarRec[iPtr] == '?') && (strnicmp(o32VarRec, "NCP:", 4) == 0))
            {
              //Special Case to replace WildCards for NCP: with SQLite Wildcards (_)
              sprintf(Inrec + oPtr, "_\0");
              oPtr = strlen(Inrec);
            }
            else
            if (strnicmp(o32VarRec + iPtr, "&VR", 3) == 0)
            {
              switch (o32VarRec[iPtr+3])
              {
                case '0':
                  iVar = 0;
                break;

                case '1':
                  iVar = 256;
                break;

                case '2':
                  iVar = 256 * 2;
                break;

                case '3':
                  iVar = 256 * 3;
                break;

                case '4':
                  iVar = 256 * 4;
                break;

                case '5':
                  iVar = 256 * 5;
                break;

                case '6':
                  iVar = 256 * 6;
                break;

                case '7':
                  iVar = 256 * 7;
                break;

                case '8':
                  iVar = 256 * 8;
                break;

                case '9':
                  iVar = 256 * 9;
                break;

                /**********************************************************/
                /* Bad Var Name                                           */
                /**********************************************************/
                default:
                  iVar = -1;
                break;
              }

              if (iVar == -1)
              {
                fprintf(LogHndl, "Err: Invalid Variable: %.4s\n", o32VarRec + iPtr);
                printf("Err: Invalid Variable: %.4s\n", o32VarRec + iPtr);

                sprintf(Inrec + oPtr, "%.4s\0", o32VarRec + iPtr);
                oPtr = strlen(Inrec);
                iPtr += 3;
              }
              else
              {
                sprintf(Inrec + oPtr, "%s\0", VarArray+iVar);
                oPtr = strlen(Inrec);
                iPtr += 3;
              }
            }
            else
            {
              Inrec[oPtr] = o32VarRec[iPtr];
              oPtr++;
              Inrec[oPtr] = '\0';
            }
          }


          /****************************************************************/
          /* Now execute the Actions                                      */
          /****************************************************************/
          if (Inrec[0] == '*');
          else
          if (strlen(Inrec) < 5);
          else
          if (strnicmp(Inrec, "Lbl:", 4) == 0); // Just acknowledge its OK
          else
          if (strnicmp(Inrec, "Jmp:", 4) == 0)
          {
            // Jump to a Label (LBL:)
            RunMe = 0;
            rewind(IniHndl);

            memset(JmpLbl, 0, 255);
            sprintf(JmpLbl, "Lbl:%.200s", Inrec + 4);
            strtok(JmpLbl, "\n"); strtok(JmpLbl, "\r");

            while (fgets(Tmprec, 1000, IniHndl))
            {
              strtok(Tmprec, "\n"); strtok(Tmprec, "\r");

              if (strnicmp(Tmprec, JmpLbl, 200) == 0)
                break;
            }
          }
          else
          if (strnicmp(Inrec, "Acq:", 4) == 0)
          {
            /****************************************************************/
            /* Create/Set ACQ Directory                                     */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            // Have we created the Base Acquisition Directory Yet?
            if (access(BACQDir, 0) != 0)
            {
              mkdir(BACQDir);
              mkdir(CachDir);
              PreIndex();
            }

            // Explicit Path
            if (Inrec[4] == '\\')
            {
              memset(ACQDir, 0, 1024);

              if (strlen(Inrec) > 5)
              {
                sprintf(ACQDir, "%s\0", Inrec + 5);
                sprintf(TempDir, "%s\\%s\0", BACQDir, ACQDir);
              }
              else
                sprintf(TempDir, "%s\0", BACQDir);
            }
            else
            {
              if (strlen(Inrec) > 4)
              {
                strcat(ACQDir, "\\\0");
                strcat(ACQDir, Inrec + 4);
                sprintf(TempDir, "%s\\%s\0", BACQDir, ACQDir);
              }
            }

            if (access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "Set: Creating Acquisition Sub-Directory: %s\n", ACQDir);
              printf("Set: Creating Acquisition Sub-Directory: %s\n", ACQDir);
              mkdir(TempDir);

              if (iHtmMode == 1)
              {
                /**********************************************************/
                /* Only Disply the FIRST Level                            */
                /**********************************************************/
                ForSlash = strrchr(TempDir, '\\');
                RootSlash = TempDir + strlen(BACQDir);

                //if (strrchr(ACQDir, '\\') == NULL)
                if (ForSlash == RootSlash)
                {
                  fprintf(HtmHndl, "</td><td align=center>\n");
                  fprintf(HtmHndl, "<a href=file:%s target=AFrame> %s </a>\n", ACQDir, ACQDir);
                }
              }
            }

            fprintf(LogHndl, "Set: Acquisition Sub-Directory Has Been Set To: %s\n", ACQDir);
            printf("Set: Acquisition Sub-Directory Has Been Set To: %s\n", ACQDir);

          }
          else
          if (strnicmp(Inrec, "Dir:", 4) == 0)
          {
            /****************************************************************/
            /* Set Current Directory                                        */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            if (Inrec[4] == '\\')
            {
              memset(CurrDir, 0, 1024);

              if (strlen(Inrec) > 5)
              {
                strncpy(CurrDir, Inrec + 5, 1000);
                sprintf(TempDir, "%s\\%s\0", BaseDir, CurrDir);
              }
              else
                sprintf(TempDir, "%s\0", BaseDir);
            }
            else
            {
              if (strlen(Inrec) > 4)
              {
                strcat(CurrDir, "\\\0");
                strcat(CurrDir, Inrec + 4);
                sprintf(TempDir, "%s\\%s\0", BaseDir, CurrDir);
              }
            }


            if (access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "Set: Creating Directory: %s\n", CurrDir);
              printf("Set: Creating Directory: %s\n", CurrDir);
              mkdir(TempDir);
            }

            fprintf(LogHndl, "Set: Directory Has Been Set To: %s\n", CurrDir);
            printf("Set: Directory Has Been Set To: %s\n", CurrDir);

          }
          else
          if (strnicmp(Inrec, "Fil:", 4) == 0)
          {
            /****************************************************************/
            /* Set Current File                                             */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            memset(CurrFil, 0, 255);
            strncpy(CurrFil, Inrec + 4, 250);

            sprintf(TempDir, "%s\\%s\0", BaseDir, CurrDir);
            if (access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "Set: Creating Directory: %s\n", CurrDir);
              printf("Set: Creating Directory: %s\n", CurrDir);
              mkdir(TempDir);
            }

            fprintf(LogHndl, "Set: File Has Been Set To: %s\n", CurrFil);
            printf("Set: File Has Been Set To: %s\n", CurrFil);

          }
          else
          if ((strnicmp(Inrec, "VR", 2) == 0) && (Inrec[3] == ':'))
          {
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            switch (Inrec[2])
            {
              case '0':
                iVar = 0;
              break;

              case '1':
                iVar = 256;
              break;

              case '2':
                iVar = 256 * 2;
              break;

              case '3':
                iVar = 256 * 3;
              break;

              case '4':
                iVar = 256 * 4;
              break;

              case '5':
                iVar = 256 * 5;
              break;

              case '6':
                iVar = 256 * 6;
              break;

              case '7':
                iVar = 256 * 7;
              break;

              case '8':
                iVar = 256 * 8;
              break;

              case '9':
                iVar = 256 * 9;
              break;
              
              /**********************************************************/
              /* Bad Var Name                                           */
              /**********************************************************/
              default:
                iVar = -1;
              break;
            }

            if (iVar == -1)
            {
              fprintf(LogHndl, "Err: Invalid Variable Define Action: %.4s\n", Inrec);
              printf("Err: Invalid Variable Define Action: %.4s\n", Inrec);
            }
            else
            {
              strncpy(VarArray+iVar, Inrec+4, 255);
            }
          }
          else
          if (strnicmp(Inrec, "Drv:", 4) == 0)
          {
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            if ((Inrec[5] == ':') && (strlen(Inrec) == 6))
            {
              strncpy(DiskDrive, Inrec + 4, 2);
              printf("Set: Disk Drive Set: %s\n", DiskDrive);
            }
            else
             printf("Err: Invalid Disk Drive Setting: %s\n", Inrec + 4);

          }
          else
          if (strnicmp(Inrec, "Ini:", 4) == 0)
          {
            /****************************************************************/
            /* Close the Old INI File and use this new one                  */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            sprintf(IniFile, "%s\0", Inrec + 4);
            if (access(IniFile, 0) != 0)
            {
              fprintf(LogHndl, "Err: Requested INI File Not Found: %s - Ignored.\n", Inrec + 4);
              printf("Err: Requested INI File Not Found: %s - Ignored.\n", Inrec + 4);
            }
            else
            {
              fprintf(LogHndl, "Inf: Switching to INI File: %s\n", Inrec + 4);
              printf("Inf: Switching to INI File: %s\n", Inrec + 4);

              fclose(IniHndl);
              IniHndl = fopen(IniFile, "r");

              if (IniHndl != NULL)
                RunMe = 0;  // Conditional run Script default is yes
              else
              {
                fprintf(LogHndl, "Err: Could Not Open INI File: %s - Exiting.\n", Inrec + 4);
                printf("Err: Could Not Open INI File: %s - Exiting.\n", Inrec + 4);
                cleanUp_Exit(3);
              }
            }
          }
          else
          if (strnicmp(Inrec, "ADM:Check", 9) == 0)
          {
            /****************************************************************/
            /* Should we Enforce Admin                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            if(iIsAdmin == 1)
            {
              printf("Inf: Running As Admin\n");
              fprintf(LogHndl, "Inf: Running As Admin\n");
            }
            else
            {
              printf("Inf: Running As NON-Admin\n");
              fprintf(LogHndl, "Inf: Running As NON-Admin\n");
            }
          }
          else
          if (strnicmp(Inrec, "ADM:Force", 9) == 0)
          {
            /****************************************************************/
            /* Should we Enforce Admin                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            if (iIsAdmin == 1)
            {
              printf("Inf: Running As Admin - Continuing....\n");
              fprintf(LogHndl, "Inf: Running As Admin - Continuing...\n");
            }
            else
            {
              printf("Err: Script IS NOT Running As Admin!\n     Please Re-Run As Admin!\n     Exiting.\n");
              fprintf(LogHndl, "Err: Running As NON-Admin\n     Please Re-Run as Admin!\n     Exiting.");
              cleanUp_Exit(3);
            }
          }
          else
          if (strnicmp(Inrec, "Inp:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            consInput(Inrec + 4, 1);
            strncpy(Inprec, Conrec, 254);
          }
          if (strnicmp(Inrec, "USB:Protect", 11) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            USB_Protect(1);
          }
          if (strnicmp(Inrec, "USB:Enable", 10) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            USB_Protect(0);
          }
          else
          if (strnicmp(Inrec, "CPY:", 4) == 0)
          {
            /****************************************************************/
            /* Binary Copy From => To                                       */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            Squish(Inrec);

            memset(Cpyrec, 0, 4096);
            strncpy(Cpyrec, Inrec + 4, 4092);
            twoSplit(Cpyrec);

            if (iPrm2 == 0)
            {
              fprintf(LogHndl, "Err: Copying Requires both a FROM and a TO File\n");
              printf("Err: Copying Requires both a FROM and a TO File\n");
            }
            else
            {
              fprintf(LogHndl, "\nCpy: %s\n     %s\n", Cpyrec + iPrm1, Cpyrec + iPrm2);
              printf("\nCpy: %s\n     %s\n", Cpyrec + iPrm1, Cpyrec + iPrm2);

              binCopy(Cpyrec + iPrm1, Cpyrec + iPrm2, 1);
            }
          }
          else
          if (strnicmp(Inrec, "NCP:", 4) == 0)
          {
            /****************************************************************/
            /* Binary Copy From => To                                       */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            Squish(Inrec);

            memset(Cpyrec, 0, 4096);
            strncpy(Cpyrec, Inrec + 4, 4092);
            twoSplit(Cpyrec);

            if (iPrm2 == 0)
            {
              fprintf(LogHndl, "Err: Raw Copying Requires both a FROM (File) and a TO (Directory)\n");
              printf("Err: Raw Copying Requires both a FROM (File)and a TO (Directory)\n");
            }
            else
            {
              fprintf(LogHndl, "\nNCP: %s\n     %s\n", Cpyrec + iPrm1, Cpyrec + iPrm2);
              printf("\nNCP: %s\n     %s\n", Cpyrec + iPrm1, Cpyrec + iPrm2);

              rawCopy(Cpyrec + iPrm1, Cpyrec + iPrm2, 1);
            }
          }
          else
          if ((strnicmp(Inrec, "ARN:", 4) == 0) && (strlen(Inrec) > 6))
          {
            /****************************************************************/
            /* Dump AutoRun Keys from OFFLINE Registry in Command           */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            Squish(Inrec);

            fprintf(LogHndl, "\nArn: Parsing Offline Registry AutoRun Keys:\n     %s\n", Inrec + 4);
            printf("\nArn: Parsing Offline Registry AutoRun Keys:\n     %s\n", Inrec + 4);


            /****************************************************************/
            /* Lets generate a Full Path Name to get the drive letter       */
            /****************************************************************/
            rcDword = GetFullPathName(Inrec + 4, FILENAME_MAX, FullFName, NULL);


            /****************************************************************/
            /* Convert the File Name to a Wide String first                 */
            /****************************************************************/
            convertedChars = 0;
            sizeofChars = strlen(Inrec + 3); // Really its +4 but we want a 1 byte buffer
            mbstowcs_s(&convertedChars, lpORFName, sizeofChars, Inrec + 4, _TRUNCATE);
            
                          
            /****************************************************************/
            /* Open the Offline Registry Hive                               */
            /****************************************************************/
            if (OROpenHive(lpORFName, &ORhKey) != ERROR_SUCCESS)
            {
              fprintf(LogHndl, "Arn: COULD NOT Open Offline Registry: %ls\n", lpORFName);
              printf("Arn: COULD NOT Open Offline Registry: %ls\n", lpORFName);
              break;
            }
              

            /****************************************************************/
            /* Run Registry Scan Twice - First Time Native,                 */
            /*              2nd Time Check Wow6432Node Keys                 */
            /****************************************************************/
            for (samLoop = 0; samLoop < 2; samLoop++)
            {
              /****************************************************************/
              /* Dump Offline Registry AutoRun Keys                           */
              /****************************************************************/
              if (samLoop == 0)
                OpenK = OROpenKey(ORhKey, ORlpSubKey, &ORphkResult);
              else
                OpenK = OROpenKey(ORhKey, ORlp6432, &ORphkResult);

              if (OpenK == ERROR_SUCCESS)
              {
                for (dwIndex = 0; dwIndex < 1000; dwIndex++)
                {
                  lpcchValueName = 2048;
                  lpcbData = 2048;

                  OpenRC = OREnumValue(ORphkResult, dwIndex, ORlpValueName, &lpcchValueName, NULL, (LPBYTE)lpData, &lpcbData);
                  if (OpenRC == ERROR_SUCCESS)
                  {
                    /****************************************************************/
                    /* Parse out the .exe - Ignore quotes                           */
                    /****************************************************************/
                    memset(Arnrec, 0, 2048);
                    memset(Cpyrec, 0, 4096);


                    /****************************************************************/
                    /* Check for possibl caller program (rundll32, cmd, etc...)     */
                    /****************************************************************/
                    snprintf(Arnrec, 2047, "%ls\0", (LPBYTE)lpData);
                                            
                    ArnLen = strlen(Arnrec);
                    for (ArnPtr = 0; ArnPtr < ArnLen; ArnPtr++)
                    {
                      if (strnicmp(Arnrec + ArnPtr, "rundll32", 8) == 0)
                        ArnPtr += 7;
                      else
                      if (strnicmp(Arnrec + ArnPtr, "rundll32.exe", 12) == 0)
                        ArnPtr += 11;
                      else
                      if (strnicmp(Arnrec + ArnPtr, "cmd /c", 6) == 0)
                        ArnPtr += 5;
                      else
                       if (strnicmp(Arnrec + ArnPtr, "cmd.exe /c", 10) == 0)
                        ArnPtr += 9;
                      else
                      if (Arnrec[ArnPtr] == ' ');
                      else
                      if (Arnrec[ArnPtr] == '"');
                      else
                       break;
                    }
                    iPtr1 = Arnrec + ArnPtr;

                    /****************************************************************/
                    /* Check for .dll or .exe                                       */
                    /****************************************************************/
                    iPtr2 = stristr(Arnrec, ".dll");
                    if (iPtr2 > 0)
                      iPtr2[4] = '\0';
                    else
                    {
                      iPtr2 = stristr(Arnrec, ".exe");
                      if (iPtr2 > 0)
                        iPtr2[4] = '\0';
                    }
                    
                    if ((iPtr3 = strrchr(iPtr1, '\\')) != NULL)
                    {
                      if (strlen(iPtr3 + 1) > 1)
                        iPtr3++;
                      else
                        iPtr3 = iPtr1;
                    }
                    else
                      iPtr3 = iPtr1;


                    /****************************************************************/
                    /* If the program is there, Copy it                             */
                    /****************************************************************/
                    varConvert(iPtr1);


                    /****************************************************************/
                    /* Substitute the drive letter from the Full path               */
                    /*  I am doing this because in a deadbox analysis, the registry */
                    /*  entries would point to the system drive - BUT since this is */
                    /*  an Offline Registry, It likely points to a mounted drive    */
                    /*  which will probably have a different drive letter.  So we   */
                    /*  assume here that the Reg and Progs will be the same drive   */
                    /****************************************************************/
                    if (o32VarRec[1] == ':')
                      o32VarRec[0] = FullFName[0];

                    if (o64VarRec[1] == ':')
                      o64VarRec[0] = FullFName[0];

                    if (access(o32VarRec, 0) == 0)
                    {
                      sprintf(Cpyrec, "%s\\%s\\%ls-%s\0", BACQDir, ACQDir, ORlpValueName, iPtr3);

                      fprintf(LogHndl, "\nArn: %ls\n     %s\n", ORlpValueName, o32VarRec);
                      printf("\nArn: %ls\n     %s\n", ORlpValueName, o32VarRec);

                      binCopy(o32VarRec, Cpyrec, 1);
                    }
                    else
                    {
                      fprintf(LogHndl, "\nArn: Not Found - %ls\n     %s\n", ORlpValueName, o32VarRec);
                      printf("\nArn: Not Found - %ls\n     %s\n", ORlpValueName, o32VarRec);
                    }


                    /****************************************************************/
                    /* Always check for 64bit versions - Since this is DeadBox      */
                    /****************************************************************/
                    if (access(o64VarRec, 0) == 0)
                    {
                      sprintf(Cpyrec, "%s\\%s\\%ls(64)-%s\0", BACQDir, ACQDir, ORlpValueName, iPtr3);

                      fprintf(LogHndl, "\nArn: (64bit)%ls\n     %s\n", ORlpValueName, o64VarRec);
                      printf("\nArn: (64bit)%Ls\n     %s\n", ORlpValueName, o64VarRec);

                      binCopy(o64VarRec, Cpyrec, 1);
                    }
                    else
                    {
                      fprintf(LogHndl, "\nArn: Not Found (64bit) - %ls\n     %s\n", ORlpValueName, o64VarRec);
                      printf("\nArn: Not Found (64bit) - %ls\n     %s\n", ORlpValueName, o64VarRec);
                    }
                  }
                  else
                  if (OpenRC == ERROR_NO_MORE_ITEMS)
                    break;
                  else
                    printf("Error: %d\n", OpenRC);
                }

                ORCloseKey(ORphkResult);
              }
              else if (OpenK == ERROR_FILE_NOT_FOUND)
                printf("\nArn: Run Key Doesnt exist\n");
              else if (OpenK == ERROR_ACCESS_DENIED)
                printf("\nArn: Run Key Access Denied\n");
              else
                printf("\nArn: Registry Error: %d\n", OpenK);
            }
          }
          else
          if ((strnicmp(Inrec, "ARN:", 4) == 0) && (strlen(Inrec) < 7))
          {
            /****************************************************************/
            /* Dump AutoRun Keys (Live Registry)                            */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            Squish(Inrec);
            
            fprintf(LogHndl, "\nArn: Parsing Live Registry AutoRun Keys\n");
            printf("\nArn: Parsing Live Registry AutoRun Keys\n");


            /****************************************************************/
            /* If 32B - Run Registry Scan Twice - First Time Native,        */
            /*          2nd Time Disable Wow6432Node to get the Keys        */
            /****************************************************************/
            for (samLoop = 0; samLoop < 2; samLoop++)
            {
              /****************************************************************/
              /* Dump AutoRun Keys                                            */
              /****************************************************************/
              if (samLoop == 0)
                OpenK = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, &phkResult);
              else
              {
                /****************************************************************/
                /* If we are 64bit dump 32 bit Keys and visa-versa              */
                /****************************************************************/
                if (strnicmp(Procesr, "AMD64", 5) == 0)
                  OpenK = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samWOW32, &phkResult);
                else
                  OpenK = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samWOW64, &phkResult);
              }


              if (OpenK == ERROR_SUCCESS)
              {
                for (dwIndex = 0; dwIndex < 1000; dwIndex++)
                {
                  lpcchValueName = 2048;
                  lpcbData = 2048;

                  OpenRC = RegEnumValue(phkResult, dwIndex, lpValueName, &lpcchValueName, NULL, NULL, (LPBYTE)lpData, &lpcbData);
                  if (OpenRC == ERROR_SUCCESS)
                  {
                    /****************************************************************/
                    /* Parse out the .exe - Ignore quotes                           */
                    /****************************************************************/
                    memset(Arnrec, 0, 2048);
                    memset(Cpyrec, 0, 4096);


                    /****************************************************************/
                    /* Check for possibl caller program (rundll32, cmd, etc...)     */
                    /****************************************************************/
                    snprintf(Arnrec, 2047, "%s", (LPTSTR) lpData);
                    ArnLen = strlen(Arnrec);
                    for (ArnPtr = 0; ArnPtr < ArnLen; ArnPtr++)
                    {
                      if (strnicmp(Arnrec + ArnPtr, "rundll32", 8) == 0)
                        ArnPtr += 7;
                      else
                      if (strnicmp(Arnrec + ArnPtr, "rundll32.exe", 12) == 0)
                        ArnPtr += 11;
                      else
                      if (strnicmp(Arnrec + ArnPtr, "cmd /c", 6) == 0)
                        ArnPtr += 5;
                      else
                      if (strnicmp(Arnrec + ArnPtr, "cmd.exe /c", 10) == 0)
                        ArnPtr += 9;
                      else
                      if (Arnrec[ArnPtr] == ' ');
                      else
                      if (Arnrec[ArnPtr] == '"');
                      else
                        break;
                    }
                    iPtr1 = Arnrec + ArnPtr;

                    /****************************************************************/
                    /* Check for .dll or .exe                                       */
                    /****************************************************************/
                    iPtr2 = stristr(Arnrec, ".dll");
                    if (iPtr2 > 0)
                      iPtr2[4] = '\0';
                    else
                    {
                      iPtr2 = stristr(Arnrec, ".exe");
                      if (iPtr2 > 0)
                        iPtr2[4] = '\0';
                    }
                    
                    if ((iPtr3 = strrchr(iPtr1, '\\')) != NULL)
                    {
                      if (strlen(iPtr3 + 1) > 1)
                        iPtr3++;
                      else
                        iPtr3 = iPtr1;
                    }
                    else
                      iPtr3 = iPtr1;


                    /****************************************************************/
                    /* If the program is there, Copy it                             */
                    /****************************************************************/
                    varConvert(iPtr1);


                    /****************************************************************/
                    /* See if it is on an NTFS Volume                               */
                    /****************************************************************/
                    isNTFS = 0;
                    if ((o32VarRec[1] == ':') && (o32VarRec[2] == '\\'))
                    {
                      memset(rootDrive, 0, 5);
                      strncpy(rootDrive, o32VarRec, 3);

                      if (GetVolumeInformation(rootDrive, volumeName, ARRAYSIZE(volumeName), &serialNumber,
                        &maxComponentLen, &fileSystemFlags, fileSystemName, ARRAYSIZE(fileSystemName)))
                      {
                        if (strnicmp(fileSystemName, "NTFS", 4) == 0)
                          isNTFS = 1;
                      }
                    }


                    if (access(o32VarRec, 0) == 0)
                    {
                      fprintf(LogHndl, "\nArn: %s\n     %s\n", lpValueName, (LPTSTR)lpData);
                      printf("\nArn: %s\n     %s\n", lpValueName, (LPTSTR)lpData);

                      if (isNTFS == 1)
                      {
                        sprintf(Cpyrec, "%s\\%s\0", BACQDir, ACQDir);

                        fprintf(LogHndl, "     Searching %s Volume(Raw Copy)...\n", fileSystemName);
                        printf("     Searching %s Volume(Raw Copy)...\n", fileSystemName);

                        rawCopy(o32VarRec, Cpyrec, 1);
                      }
                      else
                      {
                        sprintf(Cpyrec, "%s\\%s\\%s-%s\0", BACQDir, ACQDir, lpValueName, iPtr3);
                        binCopy(o32VarRec, Cpyrec, 1);
                      }
                    }
                    else
                    {
                      fprintf(LogHndl, "\nArn: Not Found - %s\n     %s\n", lpValueName, (LPTSTR)lpData);
                      printf("\nArn: Not Found - %s\n     %s\n", lpValueName, (LPTSTR)lpData);
                    }


                    /****************************************************************/
                    /* Check for 64bit versions (if set)                            */
                    /****************************************************************/
                    if (i64x32 == 1)
                    {
                      if (access(o64VarRec, 0) == 0)
                      {
                        fprintf(LogHndl, "\nArn: (64bit)%s\n     %s\n", lpValueName, (LPTSTR)lpData);
                        printf("\nArn: (64bit)%s\n     %s\n", lpValueName, (LPTSTR)lpData);

                        if (isNTFS == 1)
                        {
                          sprintf(Cpyrec, "%s\\%s\0", BACQDir, ACQDir);

                          fprintf(LogHndl, "     Searching %s Volume(Raw Copy)...\n", fileSystemName);
                          printf("     Searching %s Volume(Raw Copy)...\n", fileSystemName);

                          rawCopy(o64VarRec, Cpyrec, 1);
                        }
                        else
                        {
                          sprintf(Cpyrec, "%s\\%s\\%s(64)-%s\0", BACQDir, ACQDir, lpValueName, iPtr3);
                          binCopy(o64VarRec, Cpyrec, 1);
                        }
                      }
                      else
                      {
                        fprintf(LogHndl, "\nArn: Not Found (64bit) - %s\n     %s\n", lpValueName, (LPTSTR) lpData);
                        printf("\nArn: Not Found (64bit) - %s\n     %s\n", lpValueName, (LPTSTR) lpData);
                      }
                    }
                  }
                  else
                  if (OpenRC == ERROR_NO_MORE_ITEMS)
                    break;
                  else
                    printf("Error: %d\n", OpenRC);
                }

                RegCloseKey(phkResult);
              }
              else if (OpenK == ERROR_FILE_NOT_FOUND)
                printf("Run Key Doesnt exist\n");
              else if (OpenK == ERROR_ACCESS_DENIED)
                printf("Run Key Access Denied\n");
              else
                printf("Registry Error: %d\n", OpenK);
            }
          }
          else
          if (strnicmp(Inrec, "RC=:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            ChkRC = atoi(Inrec + 4);

            if (LastRC != ChkRC)
              RunMe++;
          }
          else
          if (strnicmp(Inrec, "RC!:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            ChkRC = atoi(Inrec + 4);

            if (LastRC == ChkRC)
              RunMe++;
          }
          else
          if (strnicmp(Inrec, "RC<:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code < n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");
            
            ChkRC = atoi(Inrec + 4);

            if (LastRC >= ChkRC)
              RunMe++;
          }
          else
          if (strnicmp(Inrec, "RC>:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            ChkRC = atoi(Inrec + 4);

            if (LastRC <= ChkRC)
              RunMe++;
          }
          else
          if (strnicmp(Inrec, "CKY:", 4) == 0)
          {
            /****************************************************************/
            /* Check for File - If not there, bump RunMe (Dont Run)         */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            memset(ChkFile, 0, 1024);
            strncpy(ChkFile, Inrec + 4, 1000);

            if (access(ChkFile, 0) != 0)
              RunMe++;
          }
          else
          if (strnicmp(Inrec, "64B:", 4) == 0)
          {
            /****************************************************************/
            /* Only Run if we are 64 bit Architecture                       */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            if (strnicmp(Procesr, "AMD64", 5) != 0)
              RunMe++;
          }
          else
          if (strnicmp(Inrec, "32B:", 4) == 0)
          {
            /****************************************************************/
            /* Only Run if we are 32 bit Architecture                       */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");
            
            if (strnicmp(Procesr, "X86", 3) != 0)
              RunMe++;
          }
          else
          if (strnicmp(Inrec, "CKN:", 4) == 0)
          {
            /****************************************************************/
            /* Check for File - If not there, bump RunMe (Dont Run)         */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            memset(ChkFile, 0, 1024);
            strncpy(ChkFile, Inrec + 4, 1000);

            if (access(ChkFile, 0) == 0)
              RunMe++;
          }
          else
          if (strnicmp(Inrec, "REQ:", 4) == 0)
          {
            /****************************************************************/
            /* This File is REQUIRED (Or exit with an Error)                */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");
            
            if (access(Inrec + 4, 0) != 0)
            {
              fprintf(LogHndl, "Required File Not Found: %s - Exiting!\n", Inrec + 4);
              printf("Required File Not Found: %s - Exiting!\n", Inrec + 4);
              cleanUp_Exit(3);
            }
            else
            {
              fprintf(LogHndl, "Required File Found: %s\n", Inrec + 4);
              printf("Required File Found: %s\n", Inrec + 4);
            }
          }
          else
          if (strnicmp(Inrec, "SAY:", 4) == 0)
          {
            // Echo To Screen
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            fprintf(LogHndl, "%s\n", Inrec + 4);
            printf("%s\n", Inrec + 4);
          }
          else
          if (strnicmp(Inrec, "PZZ:", 4) == 0)
          {
            /****************************************************************/
            /* Echo and Pause                                               */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");
            
            fprintf(LogHndl, "%s\n", Inrec + 4);
            printf("%s\n", Inrec + 4);
            getKey = getche();

            if ((getKey == 81) || (getKey == 113))
            {
              fprintf(LogHndl, "\nYou have requested Achoir to Quit.\n");
              printf("\nYou have requested Achoir to Quit.\n");
              cleanUp_Exit(0);
            }
          }
          else
          if (strnicmp(Inrec, "HSH:ACQ", 7) == 0)
          {
            /****************************************************************/
            /* Hash The Acquisition Directory                               */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            fprintf(LogHndl, "Inf: Now Hashing Acquisition Files\n");
            printf("Inf: Now Hashing Acquisition Files\n");
            sprintf(MD5File, "%s\\ACQHash.txt\0", BACQDir);
            sprintf(TempDir, "%s\\*.*\0", BACQDir);

            MD5Hndl = fopen(MD5File, "w");
            if (MD5Hndl != NULL)
            {
              ListDir(TempDir, "MD5");
              fclose(MD5Hndl);
            }
          }
          else
          if (strnicmp(Inrec, "HSH:Dir", 7) == 0)
          {
            /****************************************************************/
            /* Hash The Acquisition Directory                               */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");
            
            fprintf(LogHndl, "Inf: Now Hashing AChoir Files\n");
            printf("Inf: Now Hashing AChoir Files\n");
            sprintf(MD5File, "%s\\DirHash.txt\0", BaseDir);
            sprintf(TempDir, "%s\\*.*\0", BaseDir);

            MD5Hndl = fopen(MD5File, "w");
            if (MD5Hndl != NULL)
            {
              ListDir(TempDir, "MD5");
              fclose(MD5Hndl);
            }
          }
          else
          if (strnicmp(Inrec, "FOR:", 4) == 0)
          {
            /****************************************************************/
            /* Get the Directory Listing for the &For variable (Loop)       */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            //sprintf(MD5File, "%s\\ForFiles\0", BaseDir);
            sprintf(MD5File, "%s\\%s\\Cache\\ForFiles\0", BaseDir, ACQName);
            MD5Hndl = fopen(MD5File, "w");

            if (MD5Hndl != NULL)
            {
              ListDir(Inrec + 4, "FOR");
              fclose(MD5Hndl);
            }
          }
          else
          if (strnicmp(Inrec, "LST:", 4) == 0)
          {
            /****************************************************************/
            /* Get the Object Listing for the &LST variable (Loop)          */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            sprintf(LstFile, "%s\\%s\0", BaseDir, Inrec+4);
          }
          else
          if (strnicmp(Inrec, "END:", 4) == 0)
          {
            /****************************************************************/
            /* Decrement Conditional Pointer                                */
            /****************************************************************/
            if (RunMe > 0)
              RunMe--;
          }
          else
          if (strnicmp(Inrec, "BYE:", 4) == 0)
          {
            /****************************************************************/
            /* Exit the Script With LastRC (Probably Conditional)           */
            /****************************************************************/
            fprintf(LogHndl, "BYE: Exiting with RC = %d\n", LastRC);
            printf("BYE: Exiting with RC = %d\n", LastRC);

            if (access(ForFile, 0) == 0)
              unlink(ForFile);
            
            fclose(LogHndl);
            cleanUp_Exit(LastRC);
          }
          else
          if (strnicmp(Inrec, "USR:", 4) == 0)
          {
            /****************************************************************/
            /* Map to an External Drive & Set it to ACQ Directory           */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            memset(inUser, 0, 255);
            strncpy(inUser, Inrec + 4, 254);
          }
          else
          if (strnicmp(Inrec, "PWD:", 4) == 0)
          {
            /****************************************************************/
            /* Map to an External Drive & Set it to ACQ Directory           */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            memset(inPass, 0, 255);
            strncpy(inPass, Inrec + 4, 254);
          }
          else
          if (strnicmp(Inrec, "MAX:", 4) == 0)
          {
            /****************************************************************/
            /* Set Max File/Memory Size                                     */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            maxMemBytes = strtoul(Inrec+4, &pointEnd, 10);

            fprintf(LogHndl, "Inf: Max Memory/File Bytes Set: %lu\n", maxMemBytes);
            printf("Inf: Max Memory/File Bytes Set: %lu\n", maxMemBytes);
          }
          else
          if (strnicmp(Inrec, "MAP:", 4) == 0)
          {
            /****************************************************************/
            /* Map to an External Drive & Set it to ACQ Directory           */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            mapsDrive(Inrec + 4, 1);
          }
          else
          if (strnicmp(Inrec, "XIT:", 4) == 0)
          {
            /****************************************************************/
            /* Setup A Command to Run on Exit.                              */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");
            iXitCmd = 1;

            // Are we requesting an explicit path?
            if (Inrec[4] == '\\')
            {
              memset(XitCmd, 0, 4096);
              sprintf(XitCmd, "%s%s\0", BaseDir, Inrec + 4);
            }
            else
            {
              memset(XitCmd, 0, 4096);
              sprintf(XitCmd, "%s\0", Inrec + 4);
            }

            fprintf(LogHndl, "\nExit Program Set:\nXit: %s\n", XitCmd);
            printf("\nExit Program Set:\nXit: %s\n", XitCmd);
          }
          else
          if (strnicmp(Inrec, "SYS:", 4) == 0)
          {
            /****************************************************************/
            /* Run a system (Shell) command                                 */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            // Are we requesting an explicit path?
            if (Inrec[4] == '\\')
            {
              memset(TempDir, 0, 1024);
              sprintf(TempDir, "%s%s\0", BaseDir, Inrec + 4);
            }
            else
            {
              memset(TempDir, 0, 1024);
              sprintf(TempDir, "%s\0", Inrec + 4);
            }

            fprintf(LogHndl, "\nSys: %s\n", TempDir);
            printf("\nSys: %s\n", TempDir);
            LastRC = system(TempDir);
            fprintf(LogHndl, "Return Code: %d\n", LastRC);
          }
          else
          if (strnicmp(Inrec, "EXE:", 4) == 0)
          {
            /****************************************************************/
            /* Spawn an Executable                                          */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            Squish(Inrec);
            memset(Exerec, 0, 4096);
            strncpy(Exerec, Inrec + 4, 4092);
            twoSplit(Exerec);
            
            // Are we requesting an explicit path?
            if (Exerec[0] == '\\')
            {
              memset(TempDir, 0, 1024);
              sprintf(TempDir, "%s%s\0", BaseDir, Exerec + iPrm1);
            }
            else
            {
              memset(TempDir, 0, 1024);
              sprintf(TempDir, "%s\0", Exerec + iPrm1);
            }


            /****************************************************************/
            /* Are There Any Parms?                                         */
            /****************************************************************/
            if (access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "Err: Program Not Found\n");
              printf("Err: Program Not Found\n");
            }
            else
            {
              FileMD5(TempDir);
              if (iPrm3 > 0)
              {
                fprintf(LogHndl, "\nExe: %s\n   : %s\n   : %s\n", Exerec + iPrm1, Exerec + iPrm2, Exerec + iPrm3);
                printf("\nExe: %s\n   : %s\n   : %s\n", Exerec + iPrm1, Exerec + iPrm2, Exerec + iPrm3);
                fprintf(LogHndl, "MD5: %s\n", MD5Out);
                printf("MD5: %s\n", MD5Out);

                LastRC = (int) spawnlp(P_WAIT, TempDir, TempDir, Exerec + iPrm2, Exerec + iPrm3, NULL);
              }
              else
              if (iPrm2 > 0)
              {
                fprintf(LogHndl, "\nExe: %s\n   : %s\n", Exerec + iPrm1, Exerec + iPrm2);
                printf("\nExe: %s\n   : %s\n", Exerec + iPrm1, Exerec + iPrm2);
                fprintf(LogHndl, "MD5: %s\n", MD5Out);
                printf("MD5: %s\n", MD5Out);

                LastRC = (int) spawnlp(P_WAIT, TempDir, TempDir, Exerec + iPrm2, NULL);
              }
              else
              {
                fprintf(LogHndl, "\nExe: %s\n", Exerec + iPrm1);
                printf("\nExe: %s\n", Exerec + iPrm1);
                fprintf(LogHndl, "MD5: %s\n", MD5Out);
                printf("MD5: %s\n", MD5Out);
                LastRC = (int) spawnlp(P_WAIT, TempDir, TempDir, NULL);
              }


              if (LastRC != 0)
              {
                fprintf(LogHndl, "Spawn Error(%d): %s\n", errno, strerror(errno));
                printf("Spawn Error(%d): %s\n", errno, strerror(errno));
              }
              fprintf(LogHndl, "Return Code: %d\n", LastRC);
            }
          }
          else
          if (strnicmp(Inrec, "CMD:", 4) == 0)
          {
            /****************************************************************/
            /* Spawn an Executable using the ReactOS/AChoir command Shell   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");


            /****************************************************************/
            /* First make sure we have the CMD.EXE and the Hash is Right    */
            /****************************************************************/
            memset(CmdExe, 0, 1024);
            sprintf(CmdExe, "%s\\cmd.exe\0", BaseDir);

            if (access(CmdExe, 0) != 0)
            {
              fprintf(LogHndl, "Err: AChoir Safe Command Shell Not Found!\n");
              fprintf(LogHndl, "     Bypassing %s\n\n", Inrec);
              printf("Err: AChoir Safe Command Shell Not Found!\n");
              printf("     Bypassing %s\n\n", Inrec);
            }
            else
            {
              FileMD5(CmdExe);
              if (strnicmp(MD5Out, CmdHash, 32) != 0)
              {
                fprintf(LogHndl, "Err: Command Shell Not Approved for AChoir (Bad Hash)!\n");
                fprintf(LogHndl, "     Bypassing %s\n\n", Inrec);
                printf("Err: Command Shell Not Approved for AChoir (Bad Hash)!\n");
                printf("     Bypassing %s\n\n", Inrec);
              }
              else
              {
                Squish(Inrec);
                memset(Exerec, 0, 4096);
                strncpy(Exerec, Inrec + 4, 4092);
                twoSplit(Exerec);

                // Are we requesting an explicit path?
                if (Exerec[0] == '\\')
                {
                  memset(TempDir, 0, 1024);
                  sprintf(TempDir, "%s%s\0", BaseDir, Exerec + iPrm1);
                }
                else
                {
                  memset(TempDir, 0, 1024);
                  sprintf(TempDir, "%s\0", Exerec + iPrm1);
                }
                

                /****************************************************************/
                /* Can we Hash the File, or is it an Internal Command?          */
                /****************************************************************/
                if (access(TempDir, 0) != 0)
                 strncpy(MD5Out, "(N/A)\0", 10);
                else
                 FileMD5(TempDir);


                if (iPrm3 > 0)
                {
                  fprintf(LogHndl, "\nCMD: %s\n   : %s\n   : %s\n", Exerec + iPrm1, Exerec + iPrm2, Exerec + iPrm3);
                  printf("\nCMD: %s\n   : %s\n   : %s\n", Exerec + iPrm1, Exerec + iPrm2, Exerec + iPrm3);
                  fprintf(LogHndl, "MD5: Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);
                  printf("MD5: Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);

                  LastRC = (int)spawnlp(P_WAIT, CmdExe, CmdExe, "/c", TempDir, Exerec + iPrm2, Exerec + iPrm3, NULL);
                }
                else
                if (iPrm2 > 0)
                {
                  fprintf(LogHndl, "\nCMD: %s\n   : %s\n", Exerec + iPrm1, Exerec + iPrm2);
                  printf("\nCMD: %s\n   : %s\n", Exerec + iPrm1, Exerec + iPrm2);
                  fprintf(LogHndl, "MD5: Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);
                  printf("MD5: Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);

                  LastRC = (int)spawnlp(P_WAIT, CmdExe, CmdExe, "/c", TempDir, Exerec + iPrm2, NULL);
                }
                else
                {
                  fprintf(LogHndl, "\nCMD: %s\n", Exerec + iPrm1);
                  printf("\nCMD: %s\n", Exerec + iPrm1);
                  fprintf(LogHndl, "MD5: Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);
                  printf("MD5: Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);

                  LastRC = (int)spawnlp(P_WAIT, CmdExe, CmdExe, "/c", TempDir, NULL);
                }


                if (LastRC != 0)
                {
                  fprintf(LogHndl, "Spawn Error(%d): %s\n", errno, strerror(errno));
                  printf("Spawn Error(%d): %s\n", errno, strerror(errno));
                }
                fprintf(LogHndl, "Return Code: %d\n", LastRC);
               
              }
            }
          }
          else
          if (strnicmp(Inrec, "Get:", 4) == 0)
          {
            /****************************************************************/
            /* Use HTTP to GET a file                                       */
            /****************************************************************/
            // Ensure we are not in Run Only Mode (Mode:1)
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            sprintf(WGetFile, "%s\\%s%s\0", BaseDir, CurrDir, CurrFil);
            fprintf(LogHndl, "Inf: Getting: %s\n", WGetFile);
            printf("Inf: Getting: %s\n", WGetFile);

            unlink(WGetFile);

            WGetHndl = fopen(WGetFile, "wb");
            if (WGetHndl != NULL)
            {
              hSession = WinHttpOpen(L"WinHTTP AChoir/1.0", 
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS, 0);

              if (hSession)
              {
                /****************************************************************/
                /* Split The Domain from the File Structure                     */
                /****************************************************************/
                if (strnicmp("Get:http://", WGetURL, 11) == 0)
                  strncpy(WGetURL, Inrec + 11, 1000);
                else
                if (strnicmp("Get:https://", WGetURL, 12) == 0)
                  strncpy(WGetURL, Inrec + 12, 1000);
                else
                  strncpy(WGetURL, Inrec + 4, 1000);

                iWGetFIL = strchr(WGetURL, '/');
                iWGetFIL[0] = '\0';

                MultiByteToWideChar(0, 0, WGetURL, 2000, w_WGetURL, 1000);
                MultiByteToWideChar(0, 0, iWGetFIL+1, 2000, w_WGetFIL, 1000);
                
                hConnect = WinHttpConnect(hSession, lpWGetURL, INTERNET_DEFAULT_HTTP_PORT, 0);

                if (hConnect)
                {
                  hRequest = WinHttpOpenRequest(hConnect, L"GET", lpWGetFIL, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, NULL);
                
                  if (hRequest)
                  {
                    bResults = WinHttpSendRequest(hRequest,
                      WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                      WINHTTP_NO_REQUEST_DATA, 0,
                      0, 0);

                    if (bResults)
                    {
                      bResults = WinHttpReceiveResponse(hRequest, NULL);

                      // Keep checking for data until there is nothing left.
                      if (bResults)
                      {
                        do
                        {
                          // Check for available data.
                          dwSize = 0;
                          if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                          {
                            printf("Err: Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                            fprintf(LogHndl, "Err: Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                          }

                          if (dwSize > 0)
                          {
                            // Allocate space for the buffer.
                            pszOutBuffer = new char[dwSize + 1];
                            if (!pszOutBuffer)
                            {
                              printf("Err: Ran Out Of Memory Reading HTTP\n");
                              fprintf(LogHndl, "Err: Ran Out Of Memory Reading HTTP\n");
                              dwSize = 0;
                            }
                            else
                            {
                              // Read the data.
                              ZeroMemory(pszOutBuffer, dwSize + 1);

                              if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
                              {
                                printf("Err: Error %u in WinHttpReadData.\n", GetLastError());
                                fprintf(LogHndl, "Err: Error %u in WinHttpReadData.\n", GetLastError());
                              }
                              else
                                fwrite(pszOutBuffer, 1, dwSize, WGetHndl);
                
                              // Free the memory allocated to the buffer.
                              delete[] pszOutBuffer;
                            }
                          }
                        } while (dwSize > 0);
                      }


                      // Report any errors.
                      if (!bResults)
                      {
                        printf("Err: Error %d has occurred.\n", GetLastError());
                        fprintf(LogHndl, "Err: Error %d has occurred.\n", GetLastError());
                      }
                    }
                  }
                }

                // Close any open handles.
                if (hRequest) WinHttpCloseHandle(hRequest);
                if (hConnect) WinHttpCloseHandle(hConnect);
                if (hSession) WinHttpCloseHandle(hSession);

              }

              fclose(WGetHndl);

            }

          }
          
          /****************************************************************/
          /* End Of Script Processing Code                                */
          /****************************************************************/

        }

        if ((ForMe == 1) && (ForHndl != NULL))
          fclose(ForHndl);

        if ((LstMe == 1) && (LstHndl != NULL))
          fclose(LstHndl);

      }

    }

    fclose(IniHndl);

  }
  else
  {
    fprintf(LogHndl, "\nErr: Input Script Not Found:\n     %s\n\n", IniFile);
    printf("\nErr: Input Script Not Found:\n     %s\n\n", IniFile);
    cleanUp_Exit(1);
  }


  /****************************************************************/
  /* Cleanup                                                      */
  /****************************************************************/
  if (RunMe > 0)
  {
    fprintf(LogHndl, "Err: You have and extra END: Hanging! Check your Logic.\n");
    printf("Err: You have and extra END: Hanging! Check your Logic.\n");
  }

  cleanUp_Exit(0);

  exit(0);
}


/************************************************************/
/* This code was taken from - L. Peter Deutsch's            */
/* (ghost@aladdin.com) implementation of RFC 1321 (MD5)     */
/*                                                          */
/* Modifications to integrate the code with this program    */
/* were done by David Porco - But credit for the original   */
/* code goes to Mr Deutsch.                                 */
/*      -------------------------------------------         */
/* List Of Defines                                          */
/************************************************************/
#define T1 0xd76aa478
#define T2 0xe8c7b756
#define T3 0x242070db
#define T4 0xc1bdceee
#define T5 0xf57c0faf
#define T6 0x4787c62a
#define T7 0xa8304613
#define T8 0xfd469501
#define T9 0x698098d8
#define T10 0x8b44f7af
#define T11 0xffff5bb1
#define T12 0x895cd7be
#define T13 0x6b901122
#define T14 0xfd987193
#define T15 0xa679438e
#define T16 0x49b40821
#define T17 0xf61e2562
#define T18 0xc040b340
#define T19 0x265e5a51
#define T20 0xe9b6c7aa
#define T21 0xd62f105d
#define T22 0x02441453
#define T23 0xd8a1e681
#define T24 0xe7d3fbc8
#define T25 0x21e1cde6
#define T26 0xc33707d6
#define T27 0xf4d50d87
#define T28 0x455a14ed
#define T29 0xa9e3e905
#define T30 0xfcefa3f8
#define T31 0x676f02d9
#define T32 0x8d2a4c8a
#define T33 0xfffa3942
#define T34 0x8771f681
#define T35 0x6d9d6122
#define T36 0xfde5380c
#define T37 0xa4beea44
#define T38 0x4bdecfa9
#define T39 0xf6bb4b60
#define T40 0xbebfbc70
#define T41 0x289b7ec6
#define T42 0xeaa127fa
#define T43 0xd4ef3085
#define T44 0x04881d05
#define T45 0xd9d4d039
#define T46 0xe6db99e5
#define T47 0x1fa27cf8
#define T48 0xc4ac5665
#define T49 0xf4292244
#define T50 0x432aff97
#define T51 0xab9423a7
#define T52 0xfc93a039
#define T53 0x655b59c3
#define T54 0x8f0ccc92
#define T55 0xffeff47d
#define T56 0x85845dd1
#define T57 0x6fa87e4f
#define T58 0xfe2ce6e0
#define T59 0xa3014314
#define T60 0x4e0811a1
#define T61 0xf7537e82
#define T62 0xbd3af235
#define T63 0x2ad7d2bb
#define T64 0xeb86d391

static void
md5_process(md5_state_t *pms, const md5_byte_t *data /*[64]*/)
{
  md5_word_t
    a = pms->abcd[0], b = pms->abcd[1],
    c = pms->abcd[2], d = pms->abcd[3];
  md5_word_t t;

#ifndef ARCH_IS_BIG_ENDIAN
# define ARCH_IS_BIG_ENDIAN 1  /* slower, default implementation */
#endif
#if ARCH_IS_BIG_ENDIAN

  /*
  * On big-endian machines, we must arrange the bytes in the right
  * order.  (This also works on machines of unknown byte order.)
  */
  md5_word_t X[16];
  const md5_byte_t *xp = data;
  int i;

  for (i = 0; i < 16; ++i, xp += 4)
    X[i] = xp[0] + (xp[1] << 8) + (xp[2] << 16) + (xp[3] << 24);

#else  /* !ARCH_IS_BIG_ENDIAN */

  /*
  * On little-endian machines, we can process properly aligned data
  * without copying it.
  */
  md5_word_t xbuf[16];
  const md5_word_t *X;

  if (!((data - (const md5_byte_t *)0) & 3)) {
    /* data are properly aligned */
    X = (const md5_word_t *)data;
  }
  else {
    /* not aligned */
    memcpy(xbuf, data, 64);
    X = xbuf;
  }
#endif

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

  /* Round 1. */
  /* Let [abcd k s i] denote the operation
  a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + F(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
  /* Do the following 16 operations. */
  SET(a, b, c, d, 0, 7, T1);
  SET(d, a, b, c, 1, 12, T2);
  SET(c, d, a, b, 2, 17, T3);
  SET(b, c, d, a, 3, 22, T4);
  SET(a, b, c, d, 4, 7, T5);
  SET(d, a, b, c, 5, 12, T6);
  SET(c, d, a, b, 6, 17, T7);
  SET(b, c, d, a, 7, 22, T8);
  SET(a, b, c, d, 8, 7, T9);
  SET(d, a, b, c, 9, 12, T10);
  SET(c, d, a, b, 10, 17, T11);
  SET(b, c, d, a, 11, 22, T12);
  SET(a, b, c, d, 12, 7, T13);
  SET(d, a, b, c, 13, 12, T14);
  SET(c, d, a, b, 14, 17, T15);
  SET(b, c, d, a, 15, 22, T16);
#undef SET

  /* Round 2. */
  /* Let [abcd k s i] denote the operation
  a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + G(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
  /* Do the following 16 operations. */
  SET(a, b, c, d, 1, 5, T17);
  SET(d, a, b, c, 6, 9, T18);
  SET(c, d, a, b, 11, 14, T19);
  SET(b, c, d, a, 0, 20, T20);
  SET(a, b, c, d, 5, 5, T21);
  SET(d, a, b, c, 10, 9, T22);
  SET(c, d, a, b, 15, 14, T23);
  SET(b, c, d, a, 4, 20, T24);
  SET(a, b, c, d, 9, 5, T25);
  SET(d, a, b, c, 14, 9, T26);
  SET(c, d, a, b, 3, 14, T27);
  SET(b, c, d, a, 8, 20, T28);
  SET(a, b, c, d, 13, 5, T29);
  SET(d, a, b, c, 2, 9, T30);
  SET(c, d, a, b, 7, 14, T31);
  SET(b, c, d, a, 12, 20, T32);
#undef SET

  /* Round 3. */
  /* Let [abcd k s t] denote the operation
  a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + H(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
  /* Do the following 16 operations. */
  SET(a, b, c, d, 5, 4, T33);
  SET(d, a, b, c, 8, 11, T34);
  SET(c, d, a, b, 11, 16, T35);
  SET(b, c, d, a, 14, 23, T36);
  SET(a, b, c, d, 1, 4, T37);
  SET(d, a, b, c, 4, 11, T38);
  SET(c, d, a, b, 7, 16, T39);
  SET(b, c, d, a, 10, 23, T40);
  SET(a, b, c, d, 13, 4, T41);
  SET(d, a, b, c, 0, 11, T42);
  SET(c, d, a, b, 3, 16, T43);
  SET(b, c, d, a, 6, 23, T44);
  SET(a, b, c, d, 9, 4, T45);
  SET(d, a, b, c, 12, 11, T46);
  SET(c, d, a, b, 15, 16, T47);
  SET(b, c, d, a, 2, 23, T48);
#undef SET

  /* Round 4. */
  /* Let [abcd k s t] denote the operation
  a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + I(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
  /* Do the following 16 operations. */
  SET(a, b, c, d, 0, 6, T49);
  SET(d, a, b, c, 7, 10, T50);
  SET(c, d, a, b, 14, 15, T51);
  SET(b, c, d, a, 5, 21, T52);
  SET(a, b, c, d, 12, 6, T53);
  SET(d, a, b, c, 3, 10, T54);
  SET(c, d, a, b, 10, 15, T55);
  SET(b, c, d, a, 1, 21, T56);
  SET(a, b, c, d, 8, 6, T57);
  SET(d, a, b, c, 15, 10, T58);
  SET(c, d, a, b, 6, 15, T59);
  SET(b, c, d, a, 13, 21, T60);
  SET(a, b, c, d, 4, 6, T61);
  SET(d, a, b, c, 11, 10, T62);
  SET(c, d, a, b, 2, 15, T63);
  SET(b, c, d, a, 9, 21, T64);
#undef SET

  /* Then perform the following additions. (That is increment each
  of the four registers by the value it had before this block
  was started.) */
  pms->abcd[0] += a;
  pms->abcd[1] += b;
  pms->abcd[2] += c;
  pms->abcd[3] += d;
}

void
md5_init(md5_state_t *pms)
{
  pms->count[0] = pms->count[1] = 0;
  pms->abcd[0] = 0x67452301;
  pms->abcd[1] = 0xefcdab89;
  pms->abcd[2] = 0x98badcfe;
  pms->abcd[3] = 0x10325476;
}

void
md5_append(md5_state_t *pms, const md5_byte_t *data, int nbytes)
{
  const md5_byte_t *p = data;
  int left = nbytes;
  int offset = (pms->count[0] >> 3) & 63;
  md5_word_t nbits = (md5_word_t)(nbytes << 3);

  if (nbytes <= 0)
    return;

  /* Update the message length. */
  pms->count[1] += nbytes >> 29;
  pms->count[0] += nbits;
  if (pms->count[0] < nbits)
    pms->count[1]++;

  /* Process an initial partial block. */
  if (offset) {
    int copy = (offset + nbytes > 64 ? 64 - offset : nbytes);

    memcpy(pms->buf + offset, p, copy);
    if (offset + copy < 64)
      return;

    p += copy;
    left -= copy;
    md5_process(pms, pms->buf);
  }

  /* Process full blocks. */
  for (; left >= 64; p += 64, left -= 64)
    md5_process(pms, p);

  /* Process a final partial block. */
  if (left)
    memcpy(pms->buf, p, left);
}

void
md5_finish(md5_state_t *pms, md5_byte_t digest[16])
{
  static const md5_byte_t pad[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  md5_byte_t data[8];
  int i;

  /* Save the length before padding. */
  for (i = 0; i < 8; ++i)
    data[i] = (md5_byte_t)(pms->count[i >> 2] >> ((i & 3) << 3));
  /* Pad to 56 bytes mod 64. */
  md5_append(pms, pad, ((55 - (pms->count[0] >> 3)) & 63) + 1);
  /* Append the length. */
  md5_append(pms, data, 8);
  for (i = 0; i < 16; ++i)
    digest[i] = (md5_byte_t)(pms->abcd[i >> 2] >> ((i & 3) << 3));
}
/****************************************************************/
/* End Code                                                     */
/****************************************************************/



/**********************************************************/
/* Make an MD5 Hash from a file                           */
/**********************************************************/
int FileMD5(char *MD5FileName)
{
  md5_state_t state;
  md5_byte_t digest[16];

  int cbRead;
  int di;

  FILE *MD5Hndl;
  char buffer[1024 * 16];

  MD5Hndl = fopen(MD5FileName, "rb");

  if (MD5Hndl == NULL)
    return 0;

  cbRead = (int) fread(buffer, 1, sizeof(buffer), MD5Hndl);

  md5_init(&state);

  while (cbRead > 0)
  {
    md5_append(&state, (const md5_byte_t *)buffer, cbRead);

    cbRead = (int) fread(buffer, 1, sizeof(buffer), MD5Hndl);
  }

  md5_finish(&state, digest);

  for (di = 0; di < 16; ++di)
    sprintf(MD5Out + (di * 2), "%02x", digest[di]);

  fclose(MD5Hndl);
  return 1;
}



/***********************************************************/
/* Memory Allocation Problem                               */
/***********************************************************/
int MemAllocErr(char *ErrType)
{
  fprintf(LogHndl, "Err: Error Allocating Enough Memory For: %s\n\n", ErrType);
  printf("Err: Error Allocating Enough Memory For: %s\n\n", ErrType);

  exit(3);
  return 2;
}



/****************************************************************/
/* Squish a String to delete non-alphanumrics                   */
/****************************************************************/
size_t Squish(char *SqString)
{
  size_t Sqi, SqLen;

  //Zap any non-printable ending characters...
  for (Sqi = strlen(SqString); Sqi >= 0; Sqi--)
  {
    if ((SqString[Sqi] < 33) || (SqString[Sqi] > 126))
      SqString[Sqi] = '\0';
    else
      break;
  }

  SqLen = strlen(SqString);
  return SqLen;
}



/****************************************************************/
/* convert a record with Environment Variables in it            */
/*  - Do manual checks for 64 bit exceptions - Check both 32&64 */
/****************************************************************/
long varConvert(char *inVarRec)
{
  int  inProgress, GVNi;
  size_t Vari, Var32o, Var64o, VarLen;
  char envVarName[255] = "Temp";
  char *convVar = "C:\\Temp";

  i64x32 = 0;
  Var32o = Var64o = GVNi = 0;
  inProgress = 0;
  memset(o32VarRec, 0, 4096);
  memset(o64VarRec, 0, 4096);
  memset(envVarName, 0, 255);

  VarLen = strlen(inVarRec);
  if (VarLen > 4095)
    VarLen = 4095;

  for (Vari = 0; Vari < VarLen; Vari++)
  {
    if ((inVarRec[Vari] == '%') && (inProgress == 0))
    {
      /****************************************************************/
      /* To prevent expansion use %%                                  */
      /****************************************************************/
      if (inVarRec[Vari + 1] == '%')
      {
        o32VarRec[Var32o] = inVarRec[Vari];
        o64VarRec[Var64o] = inVarRec[Vari];
        Vari++;
        Var32o++;
        Var64o++;
      }
      else
        inProgress = 1;
    }
    else
    if ((inVarRec[Vari] == '%') && (inProgress == 1))
    {
      inProgress = 0;
      convVar = getenv(envVarName);


      /****************************************************************/
      /* Check for 32bit and 64bit differences                        */
      /****************************************************************/
      if (convVar == NULL);
      else
      if (strnicmp(convVar, "C:\\Program Files", 16) == 0)
      {
        i64x32 = 1;
        strcat(o32VarRec, "C:\\Program Files\0");
        strcat(o64VarRec, "C:\\Program Files (x86)\0");
      }
      else
      {
        strcat(o32VarRec, convVar);
        strcat(o64VarRec, convVar);
      }

      Var32o = strlen(o32VarRec);
      Var64o = strlen(o64VarRec);

      GVNi = 0;
      memset(envVarName, 0, 255);
    }
    else
    if (inProgress == 1)
    {
      envVarName[GVNi] = inVarRec[Vari];
      GVNi++;

      if (GVNi > 254)
        return 1;
    }
    else
    if (strnicmp(inVarRec + Vari, "System32", 8) == 0)
    {
      /****************************************************************/
      /* Check for System32 - (Do Checks for sysnative)               */
      /****************************************************************/
      i64x32 = 1;
      Vari += 7;

      strcat(o32VarRec, "System32\0");
      strcat(o64VarRec, "sysnative\0");

      Var32o = strlen(o32VarRec);
      Var64o = strlen(o64VarRec);
    }
    else
    {
      o32VarRec[Var32o] = inVarRec[Vari];
      o64VarRec[Var64o] = inVarRec[Vari];
      Var32o++;
      Var64o++;
    }
  }

  return 0;
}



/****************************************************************/
/* Split a string in two:                                       */
/*   * Quoted strings work                                      */
/*   * Delimiter is a space                                     */
/*                                                              */
/* iSplt=0 -- No Quote, a space is the Delimiter                */
/* iSplt=1 -- Yes Quote, a space is NOT a Delimiter             */
/* iParm=0 -- Process Parameter 1                               */
/* iParm=1 -- Process Parameter 2                               */
/* iParm=3 -- Process the rest                                  */
/*                                                              */
/****************************************************************/
long twoSplit(char *SpString)
{
  size_t SpLen, Spi;
  int  iParm, iSplt;


  iParm = iSplt = 0;
  iPrm1 = iPrm2 = iPrm3 = 0;
  SpLen = strlen(SpString);

  for (Spi = 0; Spi < SpLen; Spi++)
  {
    if ((SpString[Spi] == ' ') && (iSplt == 0))
    {
      //Split - No Pending Quote (Only if there isnt a repeating blank

      if ((SpString[Spi + 1] == ' ') && (iParm == 0));
      else
      if ((SpString[Spi + 1] == ' ') && (iParm == 1));
      else
      {
        //Set to Parameter 1, 2, 3, etc...
        iParm++;

        //For Parms greater than 1 - Ignore Split.
        if (iParm == 1)
        {
          SpString[Spi] = '\0';
          iPrm2 = Spi + 1;
        }
        else
        if (iParm == 2)
        {
          SpString[Spi] = '\0';
          iPrm3 = Spi + 1;
        }
      }
    }
    else
    if ((SpString[Spi] == '"') && (iSplt == 0))
    {
      iSplt = 1;

      if (iParm == 0)
        iPrm1 = Spi + 1;
      else
      if (iParm == 1)
        iPrm2 = Spi + 1;
      else
      if (iParm == 2)
        iPrm3 = Spi;
    }
    else
    if ((SpString[Spi] == '"') && (iSplt == 1))
    {
      iSplt = 0;

      if (iParm < 2)
        SpString[Spi] = '\0';
    }
  }
  return iParm;
}



/****************************************************************/
/*  stristr                                                     */
/****************************************************************/
char *stristr(const char *String, const char *Pattern)
{
  char *pptr, *sptr, *start;

  for (start = (char *)String; *start != NUL; start++)
  {
    /* find start of pattern in string */
    for (; ((*start != NUL) && (toupper(*start) != toupper(*Pattern))); start++);
    if (NUL == *start)
      return NULL;

    pptr = (char *)Pattern;
    sptr = (char *)start;

    while (toupper(*sptr) == toupper(*pptr))
    {
      sptr++;
      pptr++;

      /* if end of pattern then pattern was found */
      if (NUL == *pptr)
        return (start);
    }
  }
  return NULL;
}



/****************************************************************/
/* List the Directory                                           */
/****************************************************************/
int ListDir(char *DirName, char *LisType)
{
  struct _finddata_t ffblk;
  intptr_t DirDone;

  char inName[FILENAME_MAX] = " \0";
  char subDir[FILENAME_MAX] = " \0";

  char SrchDName[FILENAME_MAX] = "C:\\AChoir\0";
  char SrchFName[FILENAME_MAX] = "*.*\0";

  char *Slash;

  int iLisType;
  size_t iMaxSize;


  /****************************************************************/
  /* What type of Directory Listing                               */
  /****************************************************************/
  if (strnicmp(LisType, "MD5", 3) == 0)
    iLisType = 1;
  else
  if (strnicmp(LisType, "FOR", 3) == 0)
    iLisType = 2;
  else
  if (strnicmp(LisType, "ROS", 3) == 0)
    iLisType = 3;
  else
    iLisType = 2;


  /****************************************************************/
  /* Loop throught the directory looking for those files.         */
  /****************************************************************/
  strcpy(RootDir, DirName);

  if (iLisType == 1)
    fprintf(MD5Hndl, "Directory: %s\n", RootDir);



  /****************************************************************/
  /* Get rid of the SubDir info                                   */
  /****************************************************************/
  if ((Slash = strrchr(RootDir, '\\')) != NULL)
  {
    if (strlen(Slash + 1) > 1)
      strncpy(SrchFName, Slash + 1, 250);
    else
      strncpy(SrchFName, "*.*\0", 4);

    strncpy(Slash, "\\\0", 2);
  }



  /****************************************************************/
  /* Search Twice.                                                */
  /*  First Search ALL to parse the directories                   */
  /*  Second Search for just File Names                           */
  /****************************************************************/
  sprintf(SrchDName, "%s*.*\0", RootDir);


  /****************************************************************/
  /* First Search - Loop through Subdirectories                   */
  /****************************************************************/
  if ((DirDone = _findfirst(SrchDName, &ffblk)) != -1L)
  {
    do
    {
      if (ffblk.name[0] == '.')
        continue;

      /****************************************************************/
      /* Where are we?                                                */
      /****************************************************************/
      memset(inName, 0, FILENAME_MAX);
      strcpy(inName, ffblk.name);

      iMaxSize = strlen(RootDir);
      iMaxSize += strlen(inName);
      if (iMaxSize >= FILENAME_MAX)
      {
        fprintf(LogHndl, "Err: Max Path Exceeded: %s%s\n", RootDir, inName);
        printf("Err: Max Path Exceeded: %s%s\n", RootDir, inName);

        return 0;
      }

      if (stristr(RootDir, "Application Data\\Application Data\\Application Data\0") > 0)
      {
        fprintf(LogHndl, "Err: Directory Recursion Error: %s%s\n", RootDir, inName);
        printf("Err: Directory Recursion Error: %s%s\n", RootDir, inName);

        return 0;
      }
      

      /****************************************************************/
      /* SubDirectory Search                                          */
      /****************************************************************/
      if (ffblk.attrib & _A_SUBDIR)
      {
        strcat(RootDir, inName);

        sprintf(subDir, "%s\\%s\0", RootDir, SrchFName);
        ListDir(subDir, LisType);

        /****************************************************************/
        /* Return to ..                                                 */
        /****************************************************************/
        strcpy(RootDir, DirName);

        if ((Slash = strrchr(RootDir, '\\')) != NULL)
          strncpy(Slash, "\\\0", 2);
      }

    } while (_findnext(DirDone, &ffblk) == 0);

    _findclose(DirDone);

  }


  /****************************************************************/
  /* Second Search for just File Names                            */
  /****************************************************************/
  if ((DirDone = _findfirst(DirName, &ffblk)) != -1L)
  {
    do
    {
      if (ffblk.name[0] == '.')
        continue;


      /****************************************************************/
      /* Where are we?                                                */
      /****************************************************************/
      memset(inName, 0, FILENAME_MAX);
      strcpy(inName, ffblk.name);


      /****************************************************************/
      /* Ignore SubDirectory Search - We Already Did This             */
      /****************************************************************/
      if (ffblk.attrib & _A_SUBDIR);
      else
      {
        sprintf(FullFName, "%s%s\0", RootDir, inName);

        if (iLisType == 1)
        {
          FileMD5(FullFName);
          fprintf(MD5Hndl, "File: %s - MD5: %s\n", FullFName, MD5Out);
        }
        else
        if (iLisType == 2)
          fprintf(MD5Hndl, "%s\n", FullFName);
        else
        if (iLisType == 3)
          SetFileAttributes(FullFName, 0x1);
      }

    } while (_findnext(DirDone, &ffblk) == 0);

    _findclose(DirDone);

  }

  return 0;
}



/****************************************************************/
/* Build The Initial Artfact Index.htm                          */
/****************************************************************/
int PreIndex()
{
  iHtmMode = 0;
  sprintf(HtmFile, "%s\\Index.htm\0", BACQDir);

  HtmHndl = fopen(HtmFile, "w");
  if (HtmHndl != NULL)
  {
    iHtmMode = 1;

    fprintf(HtmHndl, "<html><head><title>AChoir Artifacts</title></head>\n");
    fprintf(HtmHndl, "<body>\n");
    fprintf(HtmHndl, "<h2>Welcome to AChoir %s</h2>\n\n", Version);
    fprintf(HtmHndl, "<p>\n");
    fprintf(HtmHndl, "Below is an Index of the Artifacts gathered for Acquisition: <b>%s</b>\n\n", ACQName);
    fprintf(HtmHndl, "</p>\n\n");
    fprintf(HtmHndl, "<table width=900>\n");
    fprintf(HtmHndl, "<tr><td align=left>\n");
    fprintf(HtmHndl, "<button onclick=\"window.history.back()\">&lt;&lt;</button>\n");
    fprintf(HtmHndl, "</td><td align=center>\n");
    fprintf(HtmHndl, "<a href=file:./ target=AFrame> Root </a>\n");
  }
  else
  {
    fprintf(HtmHndl, "Err: Could not Create Artifact Index: %s\n", HtmFile);
    printf("Err: Could not Create Artifact Index: %s\n", HtmFile);
  }

  return 0;
}



/****************************************************************/
/* Binary Copy From, To                                         */
/****************************************************************/
int binCopy(char *FrmFile, char *TooFile, int binLog)
{
  size_t inSize, outSize;
  unsigned char Cpybuf[8192];
  int NBlox = 0;

  char tmpTooFile[4096];
  int iFileCount = 0;
  int TimeNotGood = 0;
  int gotOwner = 0;
  int setOwner = 0;

  FILE* FrmHndl;
  FILE* TooHndl;
  HANDLE HndlToo;

  DWORD dwRtnCode = 0;
  DWORD SecLen, LenSec;
  PSID pSidOwner = NULL;
  PSECURITY_DESCRIPTOR SecDesc = NULL;
  BOOL pFlag = FALSE;
  char SidString[256];
  
  /****************************************************************/
  /* Make Sure the File is Not There - Don't Overwrite!           */
  /****************************************************************/
  memset(tmpTooFile, 0, 4096);
  snprintf(tmpTooFile, 4090, "%s", TooFile);

  iFileCount = 0;

  if (access(tmpTooFile, 0) == 0)
  {
    do
    {
      iFileCount++;

      memset(tmpTooFile, 0, 4096);
      snprintf(tmpTooFile, 4090, "%s(%d)", TooFile, iFileCount);
    } while (access(tmpTooFile, 0) == 0);
  }

  if ((iFileCount > 0) && (binLog == 1))
  {
    fprintf(LogHndl, "Inf: Destination File Already Exists. \n     Renamed To: %s\n", tmpTooFile);
    printf("Inf: Destination File Already Exists. \n     Renamed To: %s\n", tmpTooFile);
  }


  if (access(FrmFile, 0) != 0)
  {
    if(binLog == 1)
      fprintf(LogHndl, "Err: Source Copy File Not Found: \n %s\n", FrmFile);

    printf("Err: Source Copy File Not Found: \n %s\n", FrmFile);
  }
  else
  {
    /****************************************************************/
    /* Get the original TimeStamps                                  */
    /****************************************************************/
    stat(FrmFile, &Frmstat);


    /****************************************************************/
    /* Get the SID (File Owner) of the file - Security Descripter   */
    /****************************************************************/
    gotOwner = 0;

    // First Call is to get the Length and Malloc the buffer
    GetFileSecurity(FrmFile, OWNER_SECURITY_INFORMATION, SecDesc, 0, &SecLen);
    SecDesc = (PSECURITY_DESCRIPTOR)malloc(SecLen);

    // Second Call actually populates the Security Description Structure
    if (GetFileSecurity(FrmFile, OWNER_SECURITY_INFORMATION, SecDesc, SecLen, &LenSec))
    {
      if (GetSecurityDescriptorOwner(SecDesc, &pSidOwner, &pFlag))
      {
        gotOwner = 1;

        convert_sid_to_string_sid(pSidOwner, SidString);
      }
    }


    /****************************************************************/
    /* Copy File Code                                               */
    /****************************************************************/
    FrmHndl = fopen(FrmFile, "rb");
    TooHndl = fopen(tmpTooFile, "wb");

    if ((FrmHndl != NULL) && (TooHndl != NULL))
    {
      while ((inSize = fread(Cpybuf, 1, sizeof Cpybuf, FrmHndl)) > 0)
      {
        printf("Inf: 8K Block: %d\r", NBlox++);

        outSize = fwrite(Cpybuf, 1, inSize, TooHndl);
        if (outSize < inSize)
        {
          /****************************************************************/
          /* Somethingwent wrong - Show an error and quit                 */
          /****************************************************************/
          if (ferror(TooHndl))
          {
            if (binLog == 1)
              fprintf(LogHndl, "Err: Error Copying File (Output Error)\n");

            printf("Err: Error Copying File (Output Error)\n");
          }
          else
          {
            if (binLog == 1)
              fprintf(LogHndl, "Err: Error Copying File (Disk Full)\n");

            printf("Err: Error Copying File (Disk full)\n");
          }
          break;
        }
      }

      fclose(FrmHndl);
      fclose(TooHndl);

      /****************************************************************/
      /* Re-Set the original TimeStamps on copied file                */
      /****************************************************************/
      Time_tToFileTime(Frmstat.st_atime, 1);
      Time_tToFileTime(Frmstat.st_mtime, 2);
      Time_tToFileTime(Frmstat.st_ctime, 3);


      HndlToo = CreateFile(tmpTooFile, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

      SetFileTime(HndlToo, &ToCTime, &ToATime, &ToMTime);
      CloseHandle(HndlToo);
      

      /****************************************************************/
      /* Check to see if Windows converted it correctly               */
      /*   This code should not even be neccesary.  Alas, it is.      */
      /****************************************************************/
      stat(tmpTooFile, &Toostat);
      TimeNotGood = 0;

      // Check Create Time for wierd TZ Anomoly
      if (Frmstat.st_ctime == (Toostat.st_ctime + 3600))
      {
        TimeNotGood = 1;
        Time_tToFileTime(Frmstat.st_ctime + 3600, 3);
      }
      else
      if (Frmstat.st_ctime == (Toostat.st_ctime - 3600))
      {
        TimeNotGood = 1;
        Time_tToFileTime(Frmstat.st_ctime - 3600, 3);
      }

      // Check Modify Time for wierd TZ Anomoly
      if (Frmstat.st_mtime == (Toostat.st_mtime + 3600))
      {
        TimeNotGood = 1;
        Time_tToFileTime(Frmstat.st_mtime + 3600, 2);
      }
      else
      if (Frmstat.st_mtime == (Toostat.st_mtime - 3600))
      {
        TimeNotGood = 1;
        Time_tToFileTime(Frmstat.st_mtime - 3600, 2);
      }

      // Check Access Time for wierd TZ Anomoly
      if (Frmstat.st_atime == (Toostat.st_atime + 3600))
      {
        TimeNotGood = 1;
        Time_tToFileTime(Frmstat.st_atime + 3600, 1);
      }
      else
      if (Frmstat.st_atime == (Toostat.st_atime - 3600))
      {
        TimeNotGood = 1;
        Time_tToFileTime(Frmstat.st_atime - 3600, 1);
      }

      if (TimeNotGood == 1)
      {
        printf("Inf: Converging Mismatched TimeStamp(s)\n");

        if (binLog == 1)
          fprintf(LogHndl, "Inf: Converging Mismatched TimeStamp(s)\n");

        HndlToo = CreateFile(tmpTooFile, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        SetFileTime(HndlToo, &ToCTime, &ToATime, &ToMTime);
        CloseHandle(HndlToo);
      }
      

      /****************************************************************/
      /* Set the SID (Owner) of the new file same as the old file     */
      /****************************************************************/
      if (gotOwner == 1)
      {
        setOwner = SetFileSecurity(TooFile, OWNER_SECURITY_INFORMATION, SecDesc);
                
        if (setOwner)
        {
          printf("Inf: File Owner Set (%s)\n", SidString);
          if (binLog == 1)
            fprintf(LogHndl, "Inf: File Owner Set (%s)\n", SidString);
        }
        else
        {
          printf("Wrn: Can NOT Set Target File Owner(%s)\n", SidString);
          if (binLog == 1)
            fprintf(LogHndl, "Wrn: Can NOT Set Target File Owner (%s)\n", SidString);
        }

        if (SecDesc)
          free(SecDesc);
      }
      else
      {
        printf("Wrn: Could NOT Determine Source File Owner(Unknown)\n");
        if (binLog == 1)
          fprintf(LogHndl, "Wrn: Could NOT Determine Source File Owner (Unknown)\n");
      }



      /****************************************************************/
      /* MD5 The Files                                                */
      /****************************************************************/
      memset(MD5Tmp, 0, 255);
      FileMD5(FrmFile);
      strncpy(MD5Tmp, MD5Out, 255);
      
      if (binLog == 1)
      {
        fprintf(LogHndl, "Inf: Source File MD5.....: %s\n", MD5Out);
        fprintf(LogHndl, "Inf: Source MetaData.....: %ld-%lld-%lld-%lld\n", Frmstat.st_size, Frmstat.st_ctime, Frmstat.st_atime, Frmstat.st_mtime);
      }
      printf("Inf: Source File MD5.....: %s\n", MD5Out);
      printf("Inf: Source MetaData.....: %ld-%lld-%lld-%lld\n", Frmstat.st_size, Frmstat.st_ctime, Frmstat.st_atime, Frmstat.st_mtime);

      stat(tmpTooFile, &Toostat);
      FileMD5(tmpTooFile);
      if (binLog == 1)
      {
        fprintf(LogHndl, "Inf: Destination File MD5: %s\n", MD5Out);
        fprintf(LogHndl, "Inf: Destination MetaData: %ld-%lld-%lld-%lld\n", Toostat.st_size, Toostat.st_ctime, Toostat.st_atime, Toostat.st_mtime);
      }
      printf("Inf: Destination File MD5: %s\n", MD5Out);
      printf("Inf: Destination MetaData: %ld-%lld-%lld-%lld\n", Toostat.st_size, Toostat.st_ctime, Toostat.st_atime, Toostat.st_mtime);

      if (strnicmp(MD5Tmp, MD5Out, 255) != 0)
      {
        printf("Err: MD5 MisMatch!\n");
        if (binLog == 1)
         fprintf(LogHndl, "Err: MD5 MisMatch!\n");
      }

      if (Frmstat.st_size != Toostat.st_size)
      {
        printf("Err: Size Mismatch!\n");
        if (binLog == 1)
         fprintf(LogHndl, "Err: Size MisMatch!\n");
      }

      if (Frmstat.st_ctime != Toostat.st_ctime)
      {
        Old_CTime = localtime(&Frmstat.st_ctime);
        strftime(OldDate, 25, "%m/%d/%y@%H:%M:%S\0", Old_CTime);

        printf("Err: Create Time Mismatch! Actual Create Time: %s\n", OldDate);

        if (binLog == 1)
          fprintf(LogHndl, "Err: Create Time MisMatch! Actual Create Time: %s\n", OldDate);
      }

      if (Frmstat.st_mtime != Toostat.st_mtime)
      {
        Old_MTime = localtime(&Frmstat.st_mtime);
        strftime(OldDate, 25, "%m/%d/%y@%H:%M:%S\0", Old_MTime);

        printf("Err: Modify Time Mismatch! Actual Modify Time: %s\n", OldDate);

        if (binLog == 1)
          fprintf(LogHndl, "Err: Modify MisMatch! Actual Modify Time: %s\n", OldDate);
      }

      if (Frmstat.st_atime != Toostat.st_atime)
      {
        Old_ATime = localtime(&Frmstat.st_atime);
        strftime(OldDate, 25, "%m/%d/%y@%H:%M:%S\0", Old_ATime);

        printf("Err: Access Time Mismatch! Actual Access Time: %s\n", OldDate);

        if (binLog == 1)
          fprintf(LogHndl, "Err: Access MisMatch! Actual Access Time: %s\n", OldDate);
      }
    }
    else
    {
      if (binLog == 1)
        fprintf(LogHndl, "Err: Could Not Open File(s) for Copy\n");

      printf("Err: Could Not Open File(s) for Copy\n");
    }
  }

  return 0;
}


/****************************************************************/
/* Raw NTFS Copy From, To                                       */
/****************************************************************/
int rawCopy(char *FrmFile, char *TooFile, int binLog)
{
  CHAR drive[] = "\\\\.\\C:";
  ULONG n;

  char Full_Fname[2048] = "\0";
  int  Full_MFTID;
  int  SQL_MFT = 0;
  int  i;

  ULONGLONG File_CreDate, File_AccDate, File_ModDate;
  FILETIME File_Create, File_Access, File_Modify;
  char Text_FNCreDate[30] = "\0";
  char Text_FNAccDate[30] = "\0";
  char Text_FNModDate[30] = "\0";
  char Text_SICreDate[30] = "\0";
  char Text_SIAccDate[30] = "\0";
  char Text_SIModDate[30] = "\0";
  char Text_FileTyp[5] = "\0";
  char * pointEnd;

  DWORD SecLen, LenSec;
  PSID pSidOwner = NULL;
  BOOL pFlag = FALSE;
  char SidString[256];

  int PrivSet = 0;
  int PrivOwn = 0;
  int PrivSec = 0;
  int PrivBac = 0;
  int PrivRes = 0;

  int DDRetcd = 0;

  // Get The Drive Letter
  drive[4] = FrmFile[0];
  driveLetter[0] = FrmFile[0];
  sprintf(MFTDBFile, "%s\\%s-MFT.db\0", CachDir, driveLetter);

  //Check that we have a valid From format (x:\) - We need the Root Volume for this to work.
  if (strnicmp(FrmFile+1, ":\\\0", 2) != 0)
  {
    fprintf(LogHndl, "Inf: Invalid From File Format: %s\n", FrmFile);
    printf("Inf: Invalid From File Format: %s\n", FrmFile);
    return 1;
  }


  // Get the handle to the primary partition/volume/physical disk
  hVolume = CreateFile(drive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
  if (hVolume == INVALID_HANDLE_VALUE)
  {
    printf("Err: Could not open the Volume for Raw Access. Error: %u\n", GetLastError());
    fprintf(LogHndl, "Err: Could not open the Volume for Raw Access. Error: %u\n", GetLastError());
    return 1;
  }

  
  // Reads data from the specified input/output (I/O) device - volume / physical disk
  if (ReadFile(hVolume, &bootb, sizeof bootb, &n, 0) == 0)
  {
    printf("Err: Could not read Volume for Raw Access. Error: %u\n", GetLastError());
    fprintf(LogHndl, "Err: Could not read the Volume for Raw Access. Error: %u\n", GetLastError());
    return 1;
  }


  //Load MFT Info
  LoadMFT();

  //Super Wierd Edge Case where the Drive is Encrypted with TrueCrypt and Mounted
  if (readRetcd == 0)
    return 1;


  //If the SQLite MFT is already there - Bypass the Index Creation
  MFT_Status = 0;

  if ((_access(MFTDBFile, 0)) != -1)
    SQL_MFT = 0;
  else
    SQL_MFT = 1;


  dbrc = sqlite3_open(MFTDBFile, &dbMFTHndl);
  if (dbrc != SQLITE_OK)
  {
    printf("Could Not Open MFT Working Database : %s\n", MFTDBFile);
    fprintf(LogHndl, "Could Not Open MFT Working Database: %s\n", MFTDBFile);
    return 1;
  }


  // Make SQLite DB access as fast as possible
  dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA cache_size=4000", NULL, NULL, &errmsg);
  dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA synchronous=NORMAL", NULL, NULL, &errmsg);
  dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA journal_mode=MEMORY", NULL, NULL, &errmsg);
  dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA temp_store=MEMORY", NULL, NULL, &errmsg);

  dbMrc = sqlite3_exec(dbMFTHndl, "begin", 0, 0, &errmsg);


  if (SQL_MFT == 1)
  {
    SpinLock = 0;

    dbMQuery = sqlite3_mprintf("CREATE TABLE FileNames (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, FullFileName)\0");
    while ((dbMrc = sqlite3_exec(dbMFTHndl, dbMQuery, 0, 0, &errmsg)) != SQLITE_OK)
    {
      if (dbMrc == SQLITE_BUSY)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_LOCKED)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_ERROR)
      {
        printf("Error Creating FileNames Table\n%s\n", errmsg);
        fprintf(LogHndl, "Error Creating FileNames Table\n%s\n", errmsg);
        
        break;
      }
      else
        Sleep(100); // In windows.h
      
      /*****************************************************************/
      /* Check if we are stuck in a loop.                              */
      /*****************************************************************/
      SpinLock++;

      if (SpinLock > 25)
        break;
    }
    sqlite3_free(dbMQuery);


    SpinLock = 0;
    dbMQuery = sqlite3_mprintf("CREATE TABLE MFTFiles (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, MFTPrvID INTEGER, FileName, FileDateTyp, FNCreDate, FNAccDate, FNModDate, SICreDate, SIAccDate, SIModDate)\0");

    while ((dbMrc = sqlite3_exec(dbMFTHndl, dbMQuery, 0, 0, &errmsg)) != SQLITE_OK)
    {
      if (dbMrc == SQLITE_BUSY)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_LOCKED)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_ERROR)
      {
        printf("Error Creating MFTFiles Table\n%s\n", errmsg);
        fprintf(LogHndl, "Error Creating MFTFiles Table\n%s\n", errmsg);

        break;
      }
      else
        Sleep(100); // In windows.h

      /*****************************************************************/
      /* Check if we are stuck in a loop.                              */
      /*****************************************************************/
      SpinLock++;

      if (SpinLock > 25)
        break;
    }
    sqlite3_free(dbMQuery);


    dbMQuery = sqlite3_mprintf("CREATE TABLE MFTDirs (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, MFTPrvID INTEGER, DirsName)\0");
    while ((dbMrc = sqlite3_exec(dbMFTHndl, dbMQuery, 0, 0, &errmsg)) != SQLITE_OK)
    {
      if (dbMrc == SQLITE_BUSY)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_LOCKED)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_ERROR)
      {
        printf("Error Creating MFTDirs Table\n%s\n", errmsg);
        fprintf(LogHndl, "Error Creating MFTDirs Table\n%s\n", errmsg);

        break;
      }
      else
        Sleep(100); // In windows.h

      /*****************************************************************/
      /* Check if we are stuck in a loop.                              */
      /*****************************************************************/
      SpinLock++;

      if (SpinLock > 25)
        break;
    }
    sqlite3_free(dbMQuery);

    // The primary partition supplied else
    // default C:\ will be used
    FindActive();


    // Lets do some Test Queries Against the SQLite MFT DB 
    dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);
  }



  /************************************************************/
  /* Search for the File using SQLite                         */
  /************************************************************/
  dbMQuery = sqlite3_mprintf("Select * FROM FileNames AS T1, MFTFiles AS T2 WHERE T1.FullFileName LIKE '%q' AND T1.MFTRecID=T2.MFTRecID\0", FrmFile);

  dbMrc = sqlite3_prepare(dbMFTHndl, dbMQuery, -1, &dbMFTStmt, 0);
  if (dbMrc == SQLITE_OK)
  {
    SpinLock = 0;
    while ((dbMrc = sqlite3_step(dbMFTStmt)) != SQLITE_DONE)
    {
      if (dbMrc == SQLITE_BUSY)
        Sleep(100);
      else
      if (dbMrc == SQLITE_LOCKED)
        Sleep(100);
      else
      if (dbMrc == SQLITE_ERROR)
        Sleep(100);
      else
      if (dbMrc == SQLITE_ROW)
      {
        SpinLock = 0;
        dbMaxCol = sqlite3_column_count(dbMFTStmt);
        
        memset(Full_Fname, 0, 2048);
        for (dbi = 0; dbi < dbMaxCol; dbi++)
        {
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FullFileName", 12) == 0)
          {
            if (sqlite3_column_text(dbMFTStmt, dbi) != NULL)
              strncpy(Full_Fname, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 2000);
          }
          else
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FileDateTyp", 11) == 0)
          {
            memset(Text_FileTyp, 0, 5);
            strncpy(Text_FileTyp, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 2);
          }
          else
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "MFTRecID", 8) == 0)
          {
            Full_MFTID = sqlite3_column_int(dbMFTStmt, dbi);
          }
          else
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FNCreDate", 9) == 0)
          {
             memset(Text_FNCreDate, 0, 30);
             strncpy(Text_FNCreDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
          }
          else
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FNAccDate", 9) == 0)
          {
            memset(Text_FNAccDate, 0, 30);
            strncpy(Text_FNAccDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
          }
          else
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FNModDate", 9) == 0)
          {
            memset(Text_FNModDate, 0, 30);
            strncpy(Text_FNModDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
          }
          else
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "SICreDate", 9) == 0)
          {
            memset(Text_SICreDate, 0, 30);
            strncpy(Text_SICreDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
          }
          else
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "SIAccDate", 9) == 0)
          {
            memset(Text_SIAccDate, 0, 30);
            strncpy(Text_SIAccDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
          }
          else
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "SIModDate", 9) == 0)
          {
            memset(Text_SIModDate, 0, 30);
            strncpy(Text_SIModDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
          }
        }

        for (i = strlen(Full_Fname); i > 0; i--)
        {
          if (Full_Fname[i] == '\\')
            break;
        }

        //Prefer SI - Only use FN if we have to
        if (strnicmp(Text_FileTyp, "FN", 2) == 0)
        {
          File_CreDate = strtoull(Text_FNCreDate, &pointEnd, 10);
          File_AccDate = strtoull(Text_FNAccDate, &pointEnd, 10);
          File_ModDate = strtoull(Text_FNModDate, &pointEnd, 10);
        }
        else
        {
          File_CreDate = strtoull(Text_SICreDate, &pointEnd, 10);
          File_AccDate = strtoull(Text_SIAccDate, &pointEnd, 10);
          File_ModDate = strtoull(Text_SIModDate, &pointEnd, 10);
        }


        // Copy the Creation Date into a FILETIME structure.
        File_Create.dwLowDateTime = (DWORD)(File_CreDate & 0xFFFFFFFF);
        File_Create.dwHighDateTime = (DWORD)(File_CreDate >> 32);

        // Copy the Modified Date into a FILETIME structure.
        File_Modify.dwLowDateTime = (DWORD)(File_ModDate & 0xFFFFFFFF);
        File_Modify.dwHighDateTime = (DWORD)(File_ModDate >> 32);

        // Copy the Accessed Date into a FILETIME structure.
        File_Access.dwLowDateTime = (DWORD)(File_AccDate & 0xFFFFFFFF);
        File_Access.dwHighDateTime = (DWORD)(File_AccDate >> 32);


        /****************************************************************/
        /* Get the SID (File Owner) of the file - Security Descripter   */
        /****************************************************************/
        gotOwner = 0;

        // First Call is to get the Length and Malloc the buffer
        GetFileSecurity(Full_Fname, OWNER_SECURITY_INFORMATION, SecDesc, 0, &SecLen);
        SecDesc = (PSECURITY_DESCRIPTOR)malloc(SecLen);

        // Second Call actually populates the Security Description Structure
        if (GetFileSecurity(Full_Fname, OWNER_SECURITY_INFORMATION, SecDesc, SecLen, &LenSec))
        {
          if (GetSecurityDescriptorOwner(SecDesc, &pSidOwner, &pFlag))
          {
            gotOwner = 1;
            convert_sid_to_string_sid(pSidOwner, SidString);
          }
        }

        printf("\nInf: Raw Copying MFT File: %s (%d)\n", Full_Fname + i + 1, Full_MFTID);
        printf("    %s\n", Full_Fname);
        printf("     (In)SID: %s\n", SidString);
        printf("     (In)Time: %llu - %llu - %llu\n", File_CreDate, File_AccDate, File_ModDate);

        fprintf(LogHndl, "\nInf: Raw Copying MFT File: %s (%d)\n", Full_Fname + i + 1, Full_MFTID);
        fprintf(LogHndl, "    %s\n", Full_Fname);
        fprintf(LogHndl, "     (In)SID: %s\n", SidString);
        fprintf(LogHndl, "     (In)Time: %llu - %llu - %llu\n", File_CreDate, File_AccDate, File_ModDate);


		// Set initial Variables - Maximum File Size, Btyes Left and Recursion Depth
        maxFileSize = leftFileSize = iDepth = 0 ;

        // Return 0 if the File Copy Worked - 1 if it didnt
        DDRetcd = DumpDataII(Full_MFTID, Full_Fname + i + 1, TooFile, File_Create, File_Modify, File_Access, 1, 0);
        iDepth--;    //We Returned 
        
		if (DDRetcd == 0)
		{
		  // If we got SI and FN, Check for possible TimeStomping
		  printf("     Time Type: %s", Text_FileTyp);
		  fprintf(LogHndl, "     Time Type: %s", Text_FileTyp);

		  if (strnicmp(Text_FileTyp, "SI", 2) == 0)
		  {
		    if (strnicmp(Text_FNCreDate, Text_SICreDate, 25) != 0 ||
				strnicmp(Text_FNAccDate, Text_SIAccDate, 25) != 0 ||
				strnicmp(Text_FNAccDate, Text_SIAccDate, 25) != 0)
			{
			  printf("     Status: FN/SI Not Matched\n");
			  fprintf(LogHndl, "     Status: FN/SI Not Matched\n");
			}
			else
			{
			  printf("     Status: FN/SI Matched\n");
			  fprintf(LogHndl, "     Status: FN/SI Matched\n");
			}
		  }
		  else
		  {
			printf("     Status: FN Only\n");
			fprintf(LogHndl, "     Status: FN Only\n");
		  }
          
          if (SecDesc)
		    free(SecDesc);
		}

      }

      /*****************************************************************/
      /* Check if we are stuck in a loop.                              */
      /*****************************************************************/
      if (dbMrc != SQLITE_ROW)
      {
        SpinLock++;

        if (SpinLock > 25)
        {
          break;
        }
      }
    }
  }
  sqlite3_finalize(dbMFTStmt);
  sqlite3_free(dbMQuery);

  sqlite3_close(dbMFTHndl);
  CloseHandle(hVolume);

  //UnLoad MFT Info
  UnloadMFT();

  return 0;
}



void Time_tToFileTime(time_t InTimeT, int whichTime)
{
  /****************************************************************/
  /* This convoluted piece of code is neccesary because           */
  /*  CreateFile (necessary for GetFileTime) is super Flaky, and  */
  /*  There is no API convert from time_t to SYSTEMTIME - Sigh... */
  /****************************************************************/
  struct tm  *convgtm;      // First convert to a tm struct
  SYSTEMTIME convstm = { 0 }; // Next copy everything to a SYSTEMTIME struct
  time_t cmpTime;
  int wIsDST = -1;

  unsigned short wYear;
  unsigned short wMonth;
  unsigned short wDay;
  unsigned short wHour;
  unsigned short wMinute;
  unsigned short wSecond;
  //unsigned short wMilliseconds;

  /****************************************************************/
  /* First we Convert to tm struct                                */
  /****************************************************************/
  convgtm = gmtime(&InTimeT);


  /****************************************************************/
  /* Set DST to -1 and run gmtime to see if the time was DST      */
  /****************************************************************/
  convgtm->tm_isdst = -1;
  cmpTime = mktime(convgtm);


  /****************************************************************/
  /* Was it DST?                                                  */
  /****************************************************************/
  wIsDST = convgtm->tm_isdst;


  /****************************************************************/
  /* Get the data from the tm struct                              */
  /****************************************************************/
  wYear = convgtm->tm_year + 1900;
  wMonth = convgtm->tm_mon + 1;
  wDay = convgtm->tm_mday;
  wHour = convgtm->tm_hour;
  wMinute = convgtm->tm_min;
  wSecond = convgtm->tm_sec;


  /****************************************************************/
  /* Move it to the SYSTEMTIME struct                             */
  /****************************************************************/
  convstm.wYear = wYear;
  convstm.wMonth = wMonth;
  convstm.wDay = wDay;
  convstm.wHour = wHour;
  convstm.wMinute = wMinute;
  convstm.wSecond = wSecond;


  /****************************************************************/
  /* CTime, ATime, MTime                                          */
  /****************************************************************/
  if (whichTime == 1)
    SystemTimeToFileTime(&convstm, &ToATime);
  else
  if (whichTime == 2)
    SystemTimeToFileTime(&convstm, &ToMTime);
  else
  if (whichTime == 3)
    SystemTimeToFileTime(&convstm, &ToCTime);
  else
    SystemTimeToFileTime(&convstm, &TmpTime);
}



/****************************************************************/
/* Console Input                                                */
/****************************************************************/
long consInput(char *consString, int conLog)
{
  if(conLog == 1)
    fprintf(LogHndl, "Inp: [%s]", consString);

  printf("Inp: %s", consString);

  memset(Conrec, 0, 255);
  fgets(Conrec, 251, stdin);
  strtok(Conrec, "\n");
  strtok(Conrec, "\r");

  /****************************************************************/
  /* If our input is too long, clear the rest over 250 chars      */
  /****************************************************************/
  if (strlen(Conrec) > 249)
  {
    if(conLog == 1)
      fprintf(LogHndl, "Err: Input Truncated!\n");

    printf("Err: Input Truncated!\n");

    while ((getKey = getchar()) != '\n' && getKey != EOF);
  }

  if(conLog == 1)
    fprintf(LogHndl, "%s\n", Conrec);

  return 0;
}



/****************************************************************/
/* Map a Remote Drive                                           */
/****************************************************************/
long mapsDrive(char *mapString, int mapLog)
{
  memset(Conrec, 0, 255);
  if (strlen(mapString) < 1)
    consInput("Map: Server\\Share>", mapLog);
  else
    strncpy(Conrec, mapString, 254);


  iGoodMap = 0;
  while (iGoodMap == 0)
  {
    if(mapLog == 1)
      fprintf(LogHndl, "Map: %s\n", Conrec);

    printf("Map: %s\n", Conrec);

    netRes.dwType = RESOURCETYPE_DISK;
    netRes.lpRemoteName = Conrec;

    netRC = WNetUseConnection(NULL, &netRes, inPass, inUser, Flags, szConnection, &ConnectSize, &ConnectResult);

    if (netRC != NO_ERROR)
    {
      printf("Err: Error Mapping Resource: %s\n\n", Conrec);

      if (mapLog == 1)
        fprintf(LogHndl, "Err: Error Mapping Resource: %s\n\n", Conrec);

      printf("Map: Please Re-Enter Server\\Drive or \"quit\".\n");
      memset(Conrec, 0, 255);
      consInput("Map: Server\\Share>", mapLog);

      if (strnicmp(Conrec, "quit", 4) == 0)
      {
        printf("Err: Program Exit Requested.\n");
 
        if (mapLog == 1)
          fprintf(LogHndl, "Err: Program Exit Requested.\n");

        cleanUp_Exit(1);
      }
    }
    else
    {
      iGoodMap = 1;
      printf("Inf: Successfully Mapped %s to drive %s\n", Conrec, szConnection);

      if (mapLog == 1)
        fprintf(LogHndl, "Inf: Successfully Mapped %s to drive %s\n", Conrec, szConnection);

      strncpy(MapDrive, szConnection, 3);

      sprintf(BACQDir, "%s\\%s\0", szConnection, ACQName);
      sprintf(CachDir, "%s\\%s\\Cache\0", szConnection, ACQName);
      return 0;
    }
  }

  return 0;

}



/****************************************************************/
/* IsUserAnAdmin()                                              */
/*  Header.: Shlobj.h                                           */
/*  Library: Shell32.lib                                        */
/*  DLL....: Shell32.dll (version 5.0 or later)                 */
/*                                                              */
/* CheckTokenMembership()                                       */
/*  Header.: Winbase.h (include Windows.h)                      */
/*  Library: Advapi32.lib                                       */
/*  DLL....: Advapi32.dll                                       */
/*                                                              */
/****************************************************************/
BOOL IsUserAdmin(VOID)
{
  BOOL b;

  SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

  PSID AdministratorsGroup;

  b = AllocateAndInitializeSid(
    &NtAuthority,
    2,
    SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS,
    0, 0, 0, 0, 0, 0,
    &AdministratorsGroup);

  if (b)
  {
    if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
    {
      b = FALSE;
    }

    FreeSid(AdministratorsGroup);
  }

  return(b);

}



void showTime(char *showText)
{
  /****************************************************************/
  /* Show the TIME on console and in log                          */
  /****************************************************************/
  time_t showtimet;
  struct tm *showlocal;

  time(&showtimet);
  showlocal = localtime(&showtimet);

  if (strnicmp(showText, "&Tim", 4) == 0)
  {
    sprintf(FullDateTime, "%02d/%02d/%04d - %02d:%02d:%02d\n",
      showlocal->tm_mon + 1, showlocal->tm_mday, (showlocal->tm_year + 1900),
      showlocal->tm_hour, showlocal->tm_min, showlocal->tm_sec);
  }
  else
  {
    printf("Inf: %s: %02d/%02d/%04d - %02d:%02d:%02d\n", showText,
      showlocal->tm_mon + 1, showlocal->tm_mday, (showlocal->tm_year + 1900),
      showlocal->tm_hour, showlocal->tm_min, showlocal->tm_sec);

    fprintf(LogHndl, "Inf: %s: %02d/%02d/%04d - %02d:%02d:%02d\n", showText,
      showlocal->tm_mon + 1, showlocal->tm_mday, (showlocal->tm_year + 1900),
      showlocal->tm_hour, showlocal->tm_min, showlocal->tm_sec);
  }
}



void USB_Protect(DWORD USBOnOff)
{
  /****************************************************************/
  /* SetUSB Protection On(1) or Off(0)                            */
  /****************************************************************/
  DWORD dwUSB = REG_DWORD;
  DWORD numUSB = 0;
  DWORD cbUSB = sizeof(numUSB);
  int getLoop, gotSet;

  gotSet = 0;
  OpenK = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies", 
          NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &phkResult, NULL);
  if (OpenK == ERROR_SUCCESS)
  {
    ReadK = RegQueryValueEx(phkResult, "WriteProtect", NULL, &dwUSB, (LPBYTE)&numUSB, &cbUSB);
    if (ReadK == ERROR_SUCCESS)
    {
      if (numUSB == 0)
      {
        fprintf(LogHndl, "USB WriteProtect Key: Off\n");
        printf("USB WriteProtect Key: Off\n");
      }
      else
      {
        fprintf(LogHndl, "USB WriteProtect Key: On\n");
        printf("USB WriteProtect Key: On\n");
      }
    }
    else
    if (ReadK == ERROR_FILE_NOT_FOUND)
    {
      fprintf(LogHndl,"USB WriteProtect Key Is Empty (Off)\n");
      printf("USB WriteProtect Key Is Empty (Off)\n");
    }
    else
    {
      fprintf(LogHndl, "Error Reading USB Write Protect Key!\n");
      printf("Error Reading USB Write Protect Key!\n");
    }

    // No Need to Set it if already set 
    if (numUSB == USBOnOff)
      gotSet = 1;
    else
    {
      if (USBOnOff == 0)
      {
        fprintf(LogHndl, "Resetting WriteProtect Key To: Off\n");
        printf("Resetting WriteProtect Key To: Off\n");
      }
      else
      {
        fprintf(LogHndl, "Resetting WriteProtect Key To: On\n");
        printf("Resetting WriteProtect Key To: On\n");
      }


      MakeK = RegSetValueEx(phkResult, "WriteProtect", 0, REG_DWORD, (LPBYTE)&USBOnOff, sizeof(DWORD));
      if (MakeK == ERROR_SUCCESS)
      {
        gotSet = 1;

        fprintf(LogHndl, "USB WriteProtect Key Set Succesfully\n");
        printf("USB WriteProtect Key Set Succesfully\n");
        
        if (USBOnOff == 1)
        {
          fprintf(LogHndl, "\n Important Note: ONLY NEW ATTACHED DRIVES WILL BE WRITE PROTECTED.\n");
          printf("\n Important Note: ONLY NEW ATTACHED DRIVES WILL BE WRITE PROTECTED.\n");
        }
      }
      else
      {
        fprintf(LogHndl, "\n* * * USB WriteProtect Key WAS NOT Set Succesfully * * *\n");
        printf("\n* * * USB WriteProtect Key WAS NOT Set Succesfully * * *\n");
      }
    }
  }
  else 
    if (OpenK == ERROR_FILE_NOT_FOUND)
    {
      fprintf(LogHndl, "Could Not Open/Create USB WriteProtect Key\n");
      printf("Could Not Open/Create USB WriteProtect Key\n");
    }
  else 
  if (OpenK == ERROR_ACCESS_DENIED)
  {
    fprintf(LogHndl, "USB WriteProtect Key Access Denied\n");
    printf("USB WriteProtect Key Access Denied\n");

    if (iIsAdmin == 0)
    {
      fprintf(LogHndl, " USB WriteProtect Key Requires ADMIN Priveleges\n");
      printf(" USB WriteProtect Key Requires ADMIN Priveleges\n");
    }
  }
  else
  {
    fprintf(LogHndl, "USB WriteProtect Key Registry Error: %d\n", OpenK);
    printf("USB WriteProtect Key Registry Error: %d\n", OpenK);
  }


  if (gotSet == 0)
  {
    getLoop = 0;

    fprintf(LogHndl, "\nError Setting USB Write Protect Key!\n  Enter \"c\" to continue or \"x\" To Exit\n");
    printf("\nError Setting USB Write Protect Key!\n  Enter \"c\" to continue or \"x\" To Exit\n");

    while (getLoop == 0)
    {
      getKey = getche();
      if ((getKey == 67) || (getKey == 99))
      {
        fprintf(LogHndl, "\nYou have requested Achoir to Continue.\n");
        printf("\nYou have requested Achoir to Continue.\n");
        getLoop = 1;
      }

      if ((getKey == 88) || (getKey == 120))
      {
        fprintf(LogHndl, "\nYou have requested Achoir to Exit.\n");
        printf("\nYou have requested Achoir to Exit.\n");
        cleanUp_Exit(0);
      }
    }
  }
}



int cleanUp_Exit(int exitRC)
{
/****************************************************************/
/* Cleanup                                                      */
/****************************************************************/
if (access(ForFile, 0) == 0)
unlink(ForFile);


if (iHtmMode == 1)
{
  fprintf(HtmHndl, "</td><td align=right>\n");
  fprintf(HtmHndl, "<button onclick=\"window.history.forward()\">&gt;&gt;</button>\n");
  fprintf(HtmHndl, "</td></tr></table>\n<p>\n");
  fprintf(HtmHndl, "<iframe name=AFrame height=400 width=900 scrolling=auto src=file:./></iframe>\n");
  fprintf(HtmHndl, "</p>\n</body></html>\n");

  fclose(HtmHndl);
}


if (iRunMode == 1)
{
  fprintf(LogHndl, "Inf: Setting All Artifacts to Read-Only.\n");
  printf("Inf: Setting All Artifacts to Read-Only.\n");

  sprintf(TempDir, "%s\\*.*\0", BACQDir);
  ListDir(TempDir, "ROS");
}


/****************************************************************/
/* All Done with Acquisition                    `               */
/****************************************************************/
showTime("Acquisition Completed");

if (iXitCmd == 1)
{
  fprintf(LogHndl, "\nXit: Queuing Exit Program:\n %s\n", XitCmd);
  printf("\nXit: Queuing Exit Program:\n %s\n", XitCmd);
}

/****************************************************************/
/* Make a Copy of the Logfile in the ACQDirectory               */
/****************************************************************/
if (access(BACQDir, 0) == 0)
{
  fprintf(LogHndl, "\nInf: Copying Log File...\n");
  printf("\nInf: Copying Log File...\n");

  //Very Last Log Entry - Close Log now, and copy WITHOUT LOGGING
  fclose(LogHndl);

  sprintf(CpyFile, "%s\\ACQ-IR-%04d%02d%02d-%02d%02d.Log\0", BACQDir, iYYYY, iMonth, iDay, iHour, iMin);
  binCopy(LogFile, CpyFile, 0);
}


/****************************************************************/
/* Run Final Exit Program - This will not be logged             */
/****************************************************************/
if (iXitCmd == 1)
{
  LastRC = system(XitCmd);
}

exit(exitRC) ;
return exitRC ;

}


/****************************************************************/
/* Elevate Priveleges of Access Token                           */
/****************************************************************/
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
  TOKEN_PRIVILEGES ToknPriv;
  LUID luid;

  if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
   return FALSE;

  ToknPriv.PrivilegeCount = 1;
  ToknPriv.Privileges[0].Luid = luid;
  if (bEnablePrivilege)
    ToknPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  else
    ToknPriv.Privileges[0].Attributes = 0;

  // Enable the privilege or disable all privileges.
  if (!AdjustTokenPrivileges(hToken, FALSE, &ToknPriv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
   return FALSE;

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
   return FALSE;

  return TRUE;
}


/****************************************************************/
/* Convert a SID to a String for Display                        */
/****************************************************************/
char * convert_sid_to_string_sid(const PSID psid, char *sid_str)
{
  char tSid[32];
  DWORD iSid;

  if (!psid)
    return NULL;

  strcpy(sid_str, "S-1-");
  
  sprintf(tSid, "%u", GetSidIdentifierAuthority(psid)->Value[5]);
  strcat(sid_str, tSid);
  
  for (iSid = 0; iSid < *GetSidSubAuthorityCount(psid); ++iSid)
  {
    sprintf(tSid, "-%lu", *GetSidSubAuthority(psid, iSid));
    strcat(sid_str, tSid);
  }
  return sid_str;
}


ULONG RunLength(PUCHAR run)
{
  return (*run & 0xf) + ((*run >> 4) & 0xf) + 1;
}


LONGLONG RunLCN(PUCHAR run)
{
  LONG iRun = 0;
  UCHAR n1 = 0, n2 = 0;
  LONGLONG lcn = 0;

  n1 = *run & 0xf;
  n2 = (*run >> 4) & 0xf;
  lcn = n2 == 0 ? 0 : CHAR(run[n1 + n2]);

  for (iRun = n1 + n2 - 1; iRun > n1; iRun--)
    lcn = (lcn << 8) + run[iRun];

  return lcn;
}


ULONGLONG RunCount(PUCHAR run)
{
  UCHAR n = *run & 0xf;
  ULONGLONG count = 0;
  ULONG iRun;

  for (iRun = n; iRun > 0; iRun--)
    count = (count << 8) + run[iRun];
  return count;
}


BOOL FindRun(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, PULONGLONG lcn, PULONGLONG count)
{
  PUCHAR run = NULL;
  *lcn = 0;
  ULONGLONG base = attr->LowVcn;

  if (vcn < attr->LowVcn || vcn > attr->HighVcn)
    return FALSE;

  for (run = PUCHAR(Padd(attr, attr->RunArrayOffset)); *run != 0; run += RunLength(run))
  {
    *lcn += RunLCN(run);
    *count = RunCount(run);
    if (base <= vcn && vcn < base + *count)
    {
      *lcn = RunLCN(run) == 0 ? 0 : *lcn + vcn - base;
      *count -= ULONG(vcn - base);
      return TRUE;
    }
    else
      base += *count;
  }

  return FALSE;

}


PATTRIBUTE FindAttribute(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, PWSTR name)
{
  PATTRIBUTE attr = NULL;

  for (attr = PATTRIBUTE(Padd(file, file->AttributesOffset)); attr->AttributeType != -1; attr = Padd(attr, attr->Length))
  {
    if (attr->AttributeType == type)
    {
      if (name == 0 && attr->NameLength == 0)
        return attr;

      if (name != 0 && wcslen(name) == attr->NameLength && _wcsicmp(name, PWSTR(Padd(attr, attr->NameOffset))) == 0)
        return attr;
    }
  }
  return 0;
}


PATTRIBUTE FindAttributeX(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, PWSTR name, int attrNum)
{
  PATTRIBUTE attr = NULL;
  int FoundAttr = 0;

  for (attr = PATTRIBUTE(Padd(file, file->AttributesOffset)); attr->AttributeType != -1; attr = Padd(attr, attr->Length))
  {
    if (attr->AttributeType == type)
    {
      if (FoundAttr == attrNum)
      {
        if (name == 0 && attr->NameLength == 0)
          return attr;

        if (name != 0 && wcslen(name) == attr->NameLength && _wcsicmp(name, PWSTR(Padd(attr, attr->NameOffset))) == 0)
          return attr;
      }
      else
        FoundAttr++;
    }
  }
  return 0;
}



VOID FixupUpdateSequenceArray(PFILE_RECORD_HEADER file)
{
  ULONG iFix = 0;
  PUSHORT usa = PUSHORT(Padd(file, file->Ntfs.UsaOffset));
  PUSHORT sector = PUSHORT(file);

  for (iFix = 1; iFix < file->Ntfs.UsaCount; iFix++)
  {
    sector[255] = usa[iFix];
    sector += 256;
  }
}


VOID ReadSector(ULONGLONG sector, ULONG count, PVOID buffer)
{
  ULARGE_INTEGER offset;
  OVERLAPPED overlap = { 0 };
  ULONG n;

  offset.QuadPart = sector * bootb.BytesPerSector;
  overlap.Offset = offset.LowPart;
  overlap.OffsetHigh = offset.HighPart;

  readRetcd = ReadFile(hVolume, buffer, count * bootb.BytesPerSector, &n, &overlap);

  if (readRetcd == 0)
    printf("Err: Error Reading Sector!  Cannot Process This Volume in RAW Mode!\n");
}


VOID ReadLCN(ULONGLONG lcn, ULONG count, PVOID buffer)
{
  //wprintf(L"\nReadLCN() - Reading the LCN, LCN: 0X%.8X\n", lcn);
  ReadSector(lcn * bootb.SectorsPerCluster, count * bootb.SectorsPerCluster, buffer);
}


// Non resident attributes
VOID ReadExternalAttribute(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, ULONG count, PVOID buffer)
{
  ULONGLONG lcn, runcount;
  ULONG readcount, left;
  PUCHAR bytes = PUCHAR(buffer);

  totbytes = totdata = 0;
  for (left = count; left > 0; left -= readcount)
  {
    FindRun(attr, vcn, &lcn, &runcount);
    readcount = ULONG(min(runcount, left));
    ULONG n = readcount * bootb.BytesPerSector * bootb.SectorsPerCluster;

    if (lcn == 0)
     memset(bytes, 0, n);
    else
    {
      ReadLCN(lcn, readcount, bytes);
      //wprintf(L"LCN: 0X%.8X\n", lcn);
    }

    vcn += readcount;
    bytes += n;

    totbytes += n;
    totdata += n;
  }

  // Determine the Total Bytes Read
  if(LCNType == 1)
  {
    // Truncate the Memory Slack in the Cluster
    if(totdata > leftDataSize)
     totdata = leftDataSize;

    leftFileSize -= totbytes;
    leftDataSize -= totdata;
  }
}


ULONG AttributeLength(PATTRIBUTE attr)
{
  return attr->Nonresident == FALSE ?
    PRESIDENT_ATTRIBUTE(attr)->ValueLength :
    ULONG(PNONRESIDENT_ATTRIBUTE(attr)->DataSize);
}


ULONG AttributeLengthAllocated(PATTRIBUTE attr)
{
  return attr->Nonresident == FALSE ?
    PRESIDENT_ATTRIBUTE(attr)->ValueLength :
    ULONG(PNONRESIDENT_ATTRIBUTE(attr)->AllocatedSize);
}


ULONG AttributeLengthDataSize(PATTRIBUTE attr)
{
  return attr->Nonresident == FALSE ?
    PRESIDENT_ATTRIBUTE(attr)->ValueLength :
    ULONG(PNONRESIDENT_ATTRIBUTE(attr)->DataSize);
}


VOID ReadAttribute(PATTRIBUTE attr, PVOID buffer)
{
  PRESIDENT_ATTRIBUTE rattr = NULL;
  PNONRESIDENT_ATTRIBUTE nattr = NULL;

  if (attr->Nonresident == FALSE)
  {
    rattr = PRESIDENT_ATTRIBUTE(attr);
    memcpy(buffer, Padd(rattr, rattr->ValueOffset), rattr->ValueLength);
  }
  else
  {
    nattr = PNONRESIDENT_ATTRIBUTE(attr);
    ReadExternalAttribute(nattr, ULONG(nattr->LowVcn), ULONG(nattr->HighVcn) - ULONG(nattr->LowVcn) + 1, buffer);

  }
}


VOID ReadVCN(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, ULONGLONG vcn, ULONG count, PVOID buffer)
{
  PATTRIBUTE attrlist = NULL;
  PNONRESIDENT_ATTRIBUTE attr = PNONRESIDENT_ATTRIBUTE(FindAttribute(file, type, 0));

  if (attr == 0 || (vcn < attr->LowVcn || vcn > attr->HighVcn))
  {
    // Support for huge files
    attrlist = FindAttribute(file, AttributeAttributeList, 0);
    DebugBreak();
  }
  ReadExternalAttribute(attr, vcn, count, buffer);
}


VOID ReadFileRecord(ULONG index, PFILE_RECORD_HEADER file)
{
  ULONG clusters = bootb.ClustersPerFileRecord;

  if (clusters > 0x80)
    clusters = 1;

  PUCHAR p = new UCHAR[bootb.BytesPerSector* bootb.SectorsPerCluster * clusters];
  ULONGLONG vcn = ULONGLONG(index) * BytesPerFileRecord / bootb.BytesPerSector / bootb.SectorsPerCluster;

  ReadVCN(MFT, AttributeData, vcn, clusters, p);
  LONG m = (bootb.SectorsPerCluster * bootb.BytesPerSector / BytesPerFileRecord) - 1;
  ULONG n = m > 0 ? (index & m) : 0;

  memcpy(file, p + n * BytesPerFileRecord, BytesPerFileRecord);
  delete[] p;

  FixupUpdateSequenceArray(file);
}


VOID LoadMFT()
{
  //printf("\nInf: Locating the MFT for Raw Disk Access...\n");
  //fprintf(LogHndl, "\nInf: Locating the MFT for Raw Disk Access...\n");

  BytesPerFileRecord = bootb.ClustersPerFileRecord < 0x80
    ? bootb.ClustersPerFileRecord* bootb.SectorsPerCluster
    * bootb.BytesPerSector : 1 << (0x100 - bootb.ClustersPerFileRecord);

  MFT = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);

  ReadSector((bootb.MftStartLcn)*(bootb.SectorsPerCluster), (BytesPerFileRecord) / (bootb.BytesPerSector), MFT);

  if (readRetcd == 0)
  {
    printf("Err: Cannot Access NTFS Volume...  Bypassing...\n");
    fprintf(LogHndl, "Err: Cannot Access NTFS Volume...  Bypassing...\n");
    
    return; // Don't do anything else - We cant Acccess this Volume!
  }
  
  if (MFT->Ntfs.Type != 'ELIF')
  {
    printf("Err: Not An NTFS Volume...  Bypassing...\n");
    fprintf(LogHndl, "Err: Not An NTFS Volume...  Bypassing...\n");

    readRetcd = 0;
    return;
  }
  
  FixupUpdateSequenceArray(MFT);
}


VOID UnloadMFT()
{
  // Clean up
  //printf("Unloading the MFT...\n");
  delete[](UCHAR*)MFT;
}

BOOL bitset(PUCHAR bitmap, ULONG i)
{
  return (bitmap[i >> 3] & (1 << (i & 7))) != 0;
}


VOID FindActive()
{
  PATTRIBUTE attr = FindAttribute(MFT, AttributeBitmap, 0);
  PATTRIBUTE attr2 = attr;
  PATTRIBUTE attr3 = attr;
  PUCHAR bitmap = new UCHAR[AttributeLengthAllocated(attr)];

  PFILENAME_ATTRIBUTE name = NULL;
  PFILENAME_ATTRIBUTE name2 = NULL;
  PSTANDARD_INFORMATION name3 = NULL;

  char Full_Fname[2048] = "\0";
  char Ftmp_Fname[2048] = "\0";
  char Str_Temp1[15] = "\0";
  char Str_Temp2[15] = "\0";
  int Str_Len, Max_Files;
  int Progress, ProgUnit;
  int File_RecNum, Dir_PrevNum, File_RecID;
  int MoreDirs;
  int iLinkCount, iLink;


  //ULONGLONG File_CreDate, File_AccDate, File_ModDate;
  char Text_CreDate[30] = "\0";
  char Text_AccDate[30] = "\0";
  char Text_ModDate[30] = "\0";
  char Text_DateTyp[5] = "\0";
  char Str_Numbers[40] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\0\0\0";

  LCNType = 0; // Read Attribute Not File
  ReadAttribute(attr, bitmap);

  ULONG n = AttributeLength(FindAttribute(MFT, AttributeData, 0)) / BytesPerFileRecord;
  ProgUnit = n / 50;
  
  printf("MFT: Parsing Active Files from MFT...\n     ooooooooooo+oooooooooooo|oooooooooooo+ooooooooooo\r     ");

  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
  Progress = Max_Files = 0;
  for (ULONG i = 0; i < n; i++)
  {
    Progress++;
    if (Progress > ProgUnit)
    {
      printf(".");
      Progress = 0;
    }

    if (!bitset(bitmap, i))
      continue;

    LCNType = 0 ;
    ReadFileRecord(i, file);

    if (file->Ntfs.Type == 'ELIF' && (file->Flags == 1 || file->Flags == 3))
    {
      // See How Many Links we have - Make sure we have at least two (Short & Long FN)
      iLinkCount = file->LinkCount;
      if(iLinkCount < 1)
       iLinkCount = 1 ;

      // Bump Through Attributes and Add them to the SQLite Table
      for(iLink=0; iLink <= iLinkCount; iLink++)
      {
        // Get 0x30 (FN) Attribute
        attr = FindAttributeX(file, AttributeFileName, 0, iLink);
        if (attr == 0)
          continue;


        // Fell Through, So we got one.  Ee Said Ee already Got One!
        name = PFILENAME_ATTRIBUTE(Padd(attr, PRESIDENT_ATTRIBUTE(attr)->ValueOffset));


        // Type 0=POSIX, Type 1=Long FN, Type 2=Short FN (Ignore type 2)
        if (name->NameType == 2)
          continue;

        Str_Len = int(name->NameLength);
        wcstombs(Str_Temp, name->Name, Str_Len);
        Str_Temp[Str_Len] = '\0'; // Null Terminate the String... Sigh...
      

        // Lets Grab The SI Attribute for SI File Dates (Cre/Acc/Mod)
        attr3 = FindAttribute(file, AttributeStandardInformation, 0);
        if (attr3 != 0)
        {
          name3 = PSTANDARD_INFORMATION(Padd(attr3, PRESIDENT_ATTRIBUTE(attr3)->ValueOffset));
        }


        if (file->Flags == 1)
        {
          // Active File Entry 
          Max_Files++;

          if (attr3 == 0)
            dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileDateTyp, FNCreDate, FNAccDate, FNModDate, SICreDate, SIAccDate, SIModDate) VALUES ('%ld', '%ld', '%q', 'FN', '%llu', '%llu', '%llu', '0', '0', '0')\0",
              i, int(name->DirectoryFileReferenceNumber), Str_Temp,
              ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime),
              ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime));
          else
            dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileDateTyp, FNCreDate, FNAccDate, FNModDate, SICreDate, SIAccDate, SIModDate) VALUES ('%ld', '%ld', '%q', 'SI', '%llu', '%llu', '%llu', '%llu', '%llu', '%llu')\0",
              i, int(name->DirectoryFileReferenceNumber), Str_Temp,
              ULONGLONG(name3->CreationTime), ULONGLONG(name3->LastAccessTime), ULONGLONG(name3->LastWriteTime),
              ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime),
              ULONGLONG(name3->CreationTime), ULONGLONG(name3->LastAccessTime), ULONGLONG(name3->LastWriteTime));
        }
        else
        {
          // Active Directory Entries
          dbMQuery = sqlite3_mprintf("INSERT INTO MFTDirs (MFTRecID, MFTPrvID, DirsName) VALUES ('%ld', '%ld', '%q')\0", i, int(name->DirectoryFileReferenceNumber), Str_Temp);
        }

        SpinLock = 0;
        while ((dbMrc = sqlite3_exec(dbMFTHndl, dbMQuery, 0, 0, &errmsg)) != SQLITE_OK)
        {
          if (dbMrc == SQLITE_BUSY)
            Sleep(100); // In windows.h
          else
          if (dbMrc == SQLITE_LOCKED)
            Sleep(100); // In windows.h
          else
          if (dbMrc == SQLITE_ERROR)
          {
            printf("MFTError: Error Adding Entry to MFT SQLite Table\n%s\n", errmsg);
            MFT_Status = 2;
            break;
          }
          else
            Sleep(100); // In windows.h

         /*****************************************************************/
         /* Check if we are stuck in a loop.                              */
         /*****************************************************************/
          SpinLock++;

          if (SpinLock > 25)
            break;
        }

        sqlite3_free(dbMQuery);
      }

    }

  }


  // Create a Dirname Index for faster search
  printf("\n     Building SQLite MFT Directory Index...\r");
  dbXQuery = sqlite3_mprintf("CREATE INDEX MFTDirs_IDX ON MFTDirs(MFTRecID ASC)\0");

  SpinLock = 0;
  while ((dbXrc = sqlite3_exec(dbMFTHndl, dbXQuery, 0, 0, &errmsg)) != SQLITE_OK)
  {
    if (dbXrc == SQLITE_BUSY)
      Sleep(100); // In windows.h
    else
    if (dbXrc == SQLITE_LOCKED)
     Sleep(100); // In windows.h
    else
    if (dbXrc == SQLITE_ERROR)
    {
      printf("MFTError: Error Building Directory Index\n%s\n", errmsg);
      MFT_Status = 2;
      break;
    }
    else
      Sleep(100); // In windows.h

    /*****************************************************************/
    /* Check if we are stuck in a loop.                              */
    /*****************************************************************/
    SpinLock++;

    if (SpinLock > 25)
      break;
  }

  sqlite3_free(dbXQuery);


  // Commit Before we build the Searchable Index
  dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);

  // Begin - To speed up performance
  dbMrc = sqlite3_exec(dbMFTHndl, "begin", 0, 0, &errmsg);

  Progress = 0;
  ProgUnit = Max_Files / 50;
  wprintf(L"     Building Full Path Searchable Index...\n     ooooooooooo+oooooooooooo|oooooooooooo+ooooooooooo\r     ");


  /************************************************************/
  /* Expand out all the Files+Dirs for WildCard Searching     */
  /************************************************************/
  dbrc = sqlite3_prepare(dbMFTHndl, "select * from MFTFiles", -1, &dbMFTStmt, 0);
  if (dbrc != SQLITE_OK)
  {
    printf("MFTErr: Could Not Read MFT Database: %s\n", MFTDBFile);
    MFT_Status = 2;
    return;
  }

  SpinLock = 0;
  while ((dbrc = sqlite3_step(dbMFTStmt)) != SQLITE_DONE)
  {
    if (dbrc == SQLITE_BUSY)
      Sleep(100);
    else
    if (dbrc == SQLITE_LOCKED)
      Sleep(100);
    else
    if (dbrc == SQLITE_ERROR)
    {
      printf("MFTErr: MFT Database Error: %s\n", sqlite3_errmsg(dbMFTHndl));
      MFT_Status = 2;
      return;
    }
    else
    if (dbrc == SQLITE_ROW)
    {
      SpinLock = 0;

      memset(Ftmp_Fname, 0, 2048);
      memset(Full_Fname, 0, 2048);
      dbMaxCol = sqlite3_column_count(dbMFTStmt);

      for (dbi = 0; dbi < dbMaxCol; dbi++)
      {
        if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FileName", 8) == 0)
        {
          if (sqlite3_column_text(dbMFTStmt, dbi) != NULL)
            strncpy(Full_Fname, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 255);
        }
        else
        if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "MFTRecID", 8) == 0)
        {
          File_RecNum = sqlite3_column_int(dbMFTStmt, dbi);
          File_RecID = File_RecNum; //Save it for the Built Index
        }
        else
        if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "MFTPrvID", 8) == 0)
        {
          Dir_PrevNum = sqlite3_column_int(dbMFTStmt, dbi);
        }
      }

      // Expand out the Full File Paths
      MoreDirs = 0;
      while (MoreDirs == 0)
      {
        MoreDirs = 1; //Assume we will Exit out

        dbXQuery = sqlite3_mprintf("Select * from MFTDirs WHERE MFTRecID = '%ld'\0", Dir_PrevNum);

        dbXrc = sqlite3_prepare(dbMFTHndl, dbXQuery, -1, &dbXMFTStmt, 0);
        if (dbXrc == SQLITE_OK)
        {
          SpinLock = 0;
          while ((dbXrc = sqlite3_step(dbXMFTStmt)) != SQLITE_DONE)
          {
            if (dbXrc == SQLITE_BUSY)
              Sleep(100);
            else
            if (dbXrc == SQLITE_LOCKED)
              Sleep(100);
            else
            if (dbXrc == SQLITE_ERROR)
              Sleep(100);
            else
            if (dbXrc == SQLITE_ROW)
            {
              SpinLock = 0;

              dbMaxCol = sqlite3_column_count(dbXMFTStmt);

              memset(Ftmp_Fname, 0, 260);
              for (dbXi = 0; dbXi < dbMaxCol; dbXi++)
              {
                if (_strnicmp(sqlite3_column_name(dbXMFTStmt, dbXi), "DirsName", 8) == 0)
                {
                  if (sqlite3_column_text(dbXMFTStmt, dbXi) != NULL)
                    strncpy(Ftmp_Fname, (const char *)sqlite3_column_text(dbXMFTStmt, dbXi), 255);

                  // . is The Root (x:\)
                  if (_strnicmp(Ftmp_Fname, ".", 1) == 0)
                  {
                    sprintf(Ftmp_Fname, "%s:\\\0\0", driveLetter);
                    MoreDirs = 1; //No More Dirs
                  }
                  else
                  {
                    strcat(Ftmp_Fname, "\\\0\0");
                    MoreDirs = 0; //Lets See if we have another Directory
                  }

                  strcat(Ftmp_Fname, Full_Fname);
                  strncpy(Full_Fname, Ftmp_Fname, 2048);
                }
                else
                if (_strnicmp(sqlite3_column_name(dbXMFTStmt, dbXi), "MFTRecID", 8) == 0)
                {
                  File_RecNum = sqlite3_column_int(dbXMFTStmt, dbXi);
                }
                else
                if (_strnicmp(sqlite3_column_name(dbXMFTStmt, dbXi), "MFTPrvID", 8) == 0)
                {
                  Dir_PrevNum = sqlite3_column_int(dbXMFTStmt, dbXi);
                }
              }

              if (Dir_PrevNum == File_RecNum)
               MoreDirs = 1;
            }
          }

          /*****************************************************************/
          /* Check if we are stuck in a loop.                              */
          /*****************************************************************/
          if (dbXrc != SQLITE_ROW)
          {
            SpinLock++;

            if (SpinLock > 25)
            {
              break;
            }
          }
        }

        sqlite3_finalize(dbXMFTStmt);
        sqlite3_free(dbXQuery);
      }

      //Now Insert the Full Path FileName and MFT Record ID
      dbXQuery = sqlite3_mprintf("INSERT INTO FileNames (MFTRecID, FullFileName) VALUES ('%ld', '%q')\0", File_RecID, Full_Fname);

      SpinLock = 0;
      while ((dbXrc = sqlite3_exec(dbMFTHndl, dbXQuery, 0, 0, &errmsg)) != SQLITE_OK)
      {
        if (dbXrc == SQLITE_BUSY)
          Sleep(100); // In windows.h
        else
        if (dbXrc == SQLITE_LOCKED)
          Sleep(100); // In windows.h
        else
        if (dbXrc == SQLITE_ERROR)
        {
          printf("Err: Error Adding Entry to FileNames Table\n%s\n", errmsg);
          MFT_Status = 2;
          break;
        }
        else
          Sleep(100); // In windows.h

        /*****************************************************************/
        /* Check if we are stuck in a loop.                              */
        /*****************************************************************/
        SpinLock++;

        if (SpinLock > 25)
          break;
      }

      sqlite3_free(dbXQuery);

      Progress++;
      if (Progress > ProgUnit)
      {
        printf(".");
        Progress = 0;
      }
    }

    /*****************************************************************/
    /* Check if we are stuck in a loop.                              */
    /*****************************************************************/
    if (dbrc != SQLITE_ROW)
    {
      SpinLock++;
      if (SpinLock > 25)
      {
        break;
      }
    }
  }
  sqlite3_finalize(dbMFTStmt);
  
  // Commit The FileNames Table
  dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);

  // Create a Filename Index for faster search
  printf("\n     Building SQLite Full Path FileName Index...\n");
  dbXQuery = sqlite3_mprintf("CREATE INDEX FileNames_IDX ON FileNames(FullFileName ASC)\0");

  SpinLock = 0;
  while ((dbXrc = sqlite3_exec(dbMFTHndl, dbXQuery, 0, 0, &errmsg)) != SQLITE_OK)
  {
    if (dbXrc == SQLITE_BUSY)
      Sleep(100); // In windows.h
    else
    if (dbXrc == SQLITE_LOCKED)
      Sleep(100); // In windows.h
    else
    if (dbXrc == SQLITE_ERROR)
    {
      printf("MFTError: Error Building FileNames/FileName Index\n%s\n", errmsg);
      MFT_Status = 2;
      break;
    }
    else
      Sleep(100); // In windows.h

    /*****************************************************************/
    /* Check if we are stuck in a loop.                              */
    /*****************************************************************/
    SpinLock++;

    if (SpinLock > 25)
      break;
  }

  sqlite3_free(dbXQuery);

}


int DumpDataII(ULONG index, CHAR* filename, CHAR* outdir, FILETIME ToCreTime, FILETIME ToModTime, FILETIME ToAccTime, int binLog, int Append)
{
  PATTRIBUTE attrlist = NULL;
  PATTRIBUTE_LIST attrdata = NULL;

  PATTRIBUTE attr = NULL;
  HANDLE hFile = NULL;
  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
  ULONG n;

  FILETIME ftCreate, ftAccess, ftWrite;

  CHAR Tooo_Fname[2048] = "\0";
  int setOwner = 0;
  int iFileCount = 0;
  //long iFileSize = 0;
  long iDataSize = 0;

  PNONRESIDENT_ATTRIBUTE nonresattr = NULL;
  PATTRIBUTE_LIST attrdatax = NULL;
  ULONG MaxOffset, MaxDataSize;
  USHORT LastOffset;
  //USHORT LastDataSize;
  long pointData;
  ULONG attrLen, dataLen;
  int gotData;
 

  iDepth++;
  //Sanity Check - We should not have Attribute List Within a Data Record
  if(iDepth > 2)
  {
    if (binLog == 1)
      fprintf(LogHndl, "Inf: Recursion Too Deep - Ignoring Additional Recursion...\n");

    printf("Inf: Recursion Too Deep - Ignoring Additional Recursion...\n");

    return 0; //The Data should still be OK
  }

  memset(Tooo_Fname, 0, 2048);
  snprintf(Tooo_Fname, 2040, "%s\\%s\0", outdir, filename);
  
  if(Append == 1)
  {
    /****************************************************************/
    /* We are in Append Mode - Multiple Cluster Runs were found in  */
    /*  multiple Attribute_List MFT Records                         */
    /****************************************************************/
    if (binLog == 1)
      fprintf(LogHndl, "\nInf: Appending Data (Multiple Cluster Runs).\n");
      printf("\nInf: Appending Data (Multiple Cluster Runs).\n");
  }
  else
  {
    /****************************************************************/
    /* Single or First Cluster Run:                                 */
    /*  Make Sure the File is Not There - Don't Overwrite!          */
    /****************************************************************/
    iFileCount = 0;

    if (access(Tooo_Fname, 0) == 0)
    {
      do
      {
        iFileCount++;

        memset(Tooo_Fname, 0, 2048);
        snprintf(Tooo_Fname, 2040, "%s\\%s\\%s(%d)\0", BACQDir, ACQDir, filename, iFileCount);
      } while (access(Tooo_Fname, 0) == 0);
    }

    if (iFileCount > 0)
    {
      if (binLog == 1)
        fprintf(LogHndl, "Inf: Destination File Already Exists. \n     Renamed To: %s\n", Tooo_Fname);
      printf("Inf: Destination File Already Exists. \n     Renamed To: %s\n", Tooo_Fname);
    }
  }

  LCNType = 0;
  ReadFileRecord(index, file);

  if (file->Ntfs.Type != 'ELIF')
  {
    printf("Err: Not a Valid MFT Record...  Bypassing...\n");
    fprintf(LogHndl, "Err: Not a Valid MFT Record...  Bypassing...\n");

    return 1;
  }


  // Look for Attribute Data (0x80)
  attr = FindAttribute(file, AttributeData, 0);
  if (attr == 0)
  {
    attrlist = FindAttribute(file, AttributeAttributeList, 0);
    if (attrlist != 0)
    {
      fileIsFrag = 1;
      printf("\nInf: File is Fragmented ...  Parsing the Attribute List...\n");
      fprintf(LogHndl,"\nInf: File is Fragmented... Parsing the Attribute List...\n");

      // Read the attribute list - Physical Size and Logical Size
      //  We use Physical size to READ the clusters and Logical Size to WRITE the new file
      MaxDataSize = AttributeLengthDataSize(attrlist);
      MaxOffset = AttributeLengthAllocated(attrlist);
      
      PUCHAR bufA = new UCHAR[MaxOffset];

      LCNType = 0; // Read Attribute Not File
      ReadAttribute(attrlist, bufA);

      attrdata = PATTRIBUTE_LIST(Padd(attrlist, PRESIDENT_ATTRIBUTE(attrlist)->ValueOffset));
      LastOffset = attrdata->Length;

      gotData = 0;
      maxFileSize = maxDataSize = 0;  // Set the Max File Size.
      leftFileSize = leftDataSize = 0; // Bytes Left in the File (Multiple Cluster Runs)
      while (MaxOffset > LastOffset)
      {
        attrdatax = attrdata ;
        attrdata = PATTRIBUTE_LIST(Padd(attrdatax, attrdatax->Length));
        LastOffset += attrdatax->Length;

        // Go dump Data from Attribute Data Record (0x80)
        if (attrdata->AttributeType == AttributeData)
        {
          pointData = (LONG)attrdata->FileReferenceNumber;

          if(gotData == 0)
          {
            DumpDataII(pointData, filename, outdir, ToCreTime, ToModTime, ToAccTime, binLog, 0);
            iDepth--;    //We Returned 

            gotData = 1;
          }
          else
          {
            DumpDataII(pointData, filename, outdir, ToCreTime, ToModTime, ToAccTime, binLog, 1);
            iDepth--;    //We Returned 
          }
        }
      }

      fileIsFrag = 0;

      delete[] bufA;
    }
    else
    {
      printf("Err: No MFT File Attribute Data Found...  Bypassing...\n");
      fprintf(LogHndl, "Err: No MFT File Attribute Data Found...  Bypassing...\n");
    }
    
    return 1;
  }
  else
  {
    //Try to get the file size
    // If it is 0 - See if we are in Append and Get the number of bytes
    //  Left in the File (leftSize)
    dataLen = AttributeLengthDataSize(attr);
    attrLen = AttributeLengthAllocated(attr);
    if (attrLen > 0)
    {
      maxFileSize = attrLen;
      leftFileSize = attrLen;
      maxDataSize = dataLen;
      leftDataSize = dataLen;
    }
    else
    {
      attrLen = leftFileSize;
      dataLen = leftDataSize;
    }

    // Changing to unique Buffer bufD - To avoid conflict with attr BufA
    // Limiting File Size to 1TB - Until I can refactor this code
    if (attrLen > maxMemBytes)
    {
      printf("     (In)Size: %lu\n", attrLen);
      printf("Err: File Exceeds Max Allowed Size...  Bypassing...\n");

      if (binLog == 1)
      {
        fprintf(LogHndl, "     (In)Size: %lu\n", attrLen);
        fprintf(LogHndl, "Err: File Exceeds Max Allowed Size...  Bypassing...\n");
      }

      return 1;

    }
    
    PUCHAR bufD = new UCHAR[attrLen];
    
    LCNType = 1; // Read Actual File Clusters into buf
    ReadAttribute(attr, bufD);

    //iFileSize = maxFileSize;
    iDataSize = maxDataSize;

    //In cases where the file is Resident use maxDataSize
    if(totdata > maxDataSize)
     totdata = maxDataSize;

    printf("     (In)Size: %ld\n", iDataSize);

    if (binLog == 1)
      fprintf(LogHndl, "     (In)Size: %ld\n", iDataSize);

    printf("\nInf: Dumping Raw Data to FileName:\n    %s\n", Tooo_Fname);
  
    if (binLog == 1)
      fprintf(LogHndl, "\nInf: Dumping Raw Data to FileName:\n    %s\n", Tooo_Fname);
 
 
    if(Append == 1)
      hFile = CreateFile((LPCSTR)Tooo_Fname, FILE_APPEND_DATA, 0, 0, OPEN_ALWAYS, 0, 0);
    else
      hFile = CreateFile((LPCSTR)Tooo_Fname, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);

    if (hFile == INVALID_HANDLE_VALUE)
    {
      if (binLog == 1)
        fprintf(LogHndl, "Err: Error Creating File: %u\n", GetLastError());

      printf("Err: Error Creating File: %u\n", GetLastError());
      return 1;
    }

    if (WriteFile(hFile, bufD, totdata, &n, 0) == 0)
    {
      if (binLog == 1)
        fprintf(LogHndl, "Err: Error Writing File: %u\n", GetLastError());

      printf("Err: Error Writing File: %u\n", GetLastError());
      return 1;
    }
  
    //Set the File Times
    SetFileTime(hFile, &ToCreTime, &ToAccTime, &ToModTime);

    //Read it back out to Verify
    GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite);

    CloseHandle(hFile);

    /****************************************************************/
    /* Set the SID (Owner) of the new file same as the old file     */
    /****************************************************************/
    if (gotOwner == 1)
    {
      setOwner = SetFileSecurity(Tooo_Fname, OWNER_SECURITY_INFORMATION, SecDesc);

      if (setOwner)
      {
        if (binLog == 1)
          fprintf(LogHndl, "     (out)File Owner was Set Succesfully.\n");
        printf("     (out)File Owner was Set Succesfully.\n");
      }
      else
      {
        if (binLog == 1)
          fprintf(LogHndl, "Wrn: Could NOT Set Target File Owner.\n");
        printf("Wrn: Could NOT Set Target File Owner.\n");
      }
    }
    else
    {
      if (binLog == 1)
        fprintf(LogHndl, "Wrn: Could NOT Determine Source File Owner(Unknown)\n");
      printf("Wrn: Could NOT Determine Source File Owner(Unknown)\n");
    }

    delete[] bufD;


    /****************************************************************/
    /* MD5 The Files                                                */
    /****************************************************************/
    stat(Tooo_Fname, &Toostat);
    FileMD5(Tooo_Fname);
    if (binLog == 1)
    {
      fprintf(LogHndl, "     (out)Time: %llu - %llu - %llu\n", ftCreate, ftAccess, ftWrite);
      fprintf(LogHndl, "     (out)Size: %ld\n", Toostat.st_size);
      fprintf(LogHndl, "     (out)File MD5: %s\n", MD5Out);
    }
    printf("     (out)Time: %llu - %llu - %llu\n", ftCreate, ftAccess, ftWrite);
    printf("     (out)Size: %ld\n", Toostat.st_size);
    printf("     (out)File MD5: %s\n", MD5Out);

    if ((CompareFileTime(&ToCreTime, &ftCreate) != 0) || (CompareFileTime(&ToAccTime, &ftAccess) != 0) || (CompareFileTime(&ToModTime, &ftWrite) != 0))
    {
      printf("\nWrn: File TimeStamp MisMatch\n");
      if (binLog == 1)
        fprintf(LogHndl, "\nWrn: File TimeStamp MisMatch\n");
    }

    if (iDataSize != Toostat.st_size)
    {
      if(fileIsFrag == 1)
        printf("\nInf: File Size Fragmentation - More Data to be Appended...\n");
      else
        printf("\nWrn: File Size MisMatch\n");

      if (binLog == 1)
      { 
        if (fileIsFrag == 1)
          fprintf(LogHndl, "\nInf: File Size Fragmentation - More Data to be Appended...\n");
        else
          fprintf(LogHndl, "\nWrn: File Size MisMatch\n");
      }
    }
    else
    {
      printf("\nInf: File Sizes Match\n");

      if (binLog == 1)
        fprintf(LogHndl, "Inf: File Sizes Match\n");
    }

    return 0;
  }
}
