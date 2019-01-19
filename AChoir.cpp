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
/* AChoir v0.89 - Large File (> 1GB) Support                    */
/* AChoir v0.90 - ADD HKCU Parsing for ARN:                     */
/* AChoir v0.91 - Edge case exit Bug Fix                        */
/* AChoir v0.92 - Sig:<Typ=xxxx> Load File Type, Hex Signature  */
/*              - NCS: NTFS Copy by Signature                   */
/*                (Used together to copy Files by Signature)    */
/* AChoir v0.93 - Refactored some SQLite Code to avoid random   */
/*                 Heap Corruption issues                       */
/* AChoir v0.95 - FINALLY Fix Abend Bug in Large File Support   */
/*              - Got rid of the other attempts to fix it       */
/*              - NOTE: v0.95 will be slower than previous      */
/*                Versions. I opted for slower and safer code   */
/*                with a smaller memory footprint.              */
/* AChoir v0.96 - Clean Up some of the code, improve output.    */
/* AChoir v0.96a- Cosmetic changes to Index.htm                 */
/* AChoir v0.97 - Add Colors, Minor Bug Fixes                   */
/* AChoir v0.98 - CPS: Copy by Signature (Standard Win32 API)   */
/*                (Used with SIG: to copy Files by Signature)   */
/*                 - Not Recommended for Locked/System Files    */
/*              - Tighten Application Data recursion to 2 lvls  */
/*              - /Con or /ini:Console - Console as Input File  */
/* AChoir v0.98a- Various improvements to Interactive Mode      */
/*                - Replace conditional statements with messages*/
/*                - add INI:Console to Scripting                */
/*                - Improve switching between Script and        */
/*                   Interactive Modes                          */
/* AChoir v1.0  - Cosmetic USB Message Changes                  */
/*              - HTTP Get Bug Fixes, Fix &Acq dblSlash         */
/*              - Add Optional Case & Evidence Name/Number Input*/
/*              - CSE:GET and CSE:SAY                           */
/*              - /CSE Argument to Get Case Information         */
/*              - VCK:<x:\>  NTFS, FAT32, CDFS, Other, None     */
/*              - &VCK - Contains Results of VCK:               */
/*              - EQU:<s1> <s2> - Are S1 and S2 Equal?          */
/*              - NEQ:<s1> <s2> - Are S1 and S2 NOT Equal?      */
/*              - Support Indenting (spaces or Tabs)            */
/*              - DSK:<type>  Set &DSK looping variable to      */
/*                - Types: Removable, Fixed, Remote, CDROM      */
/*              - &DSK - Looping Var Contains Disk that match   */
/* AChoir v1.1  - Peppered Flush STDOUT buffers for better      */
/*                PSExec Display (Remote Acq)                   */
/*              - SHR:<Path> <Name> - Create a Local Share      */
/*              - SHD:<Name> - Delete a Local Share             */
/* AChoir v1.2  - Add /USR:? and /PWD:? - Query MAP USR and PWD */
/*              - Replaced getch() with getchar().  This is     */
/*                because PsExec does not work with getch().    */
/*                PsExec also does not work with SetConsoleMode */
/*                so there is no way to do hidden/masked        */
/*                password input.                               */
/* AChoir v1.3  - Implement NTP Client for Querying Time Drift  */
/*              - Fix minor display bug when using &Tim         */
/* AChoir v1.4  - New Actions to Hide and Reconnect the Console */
/*              - CON:Hide and CON:Show                         */
/*              - SLP:<Sec> Sleep for <Sec>Seconds              */
/* AChoir v1.5  - Add /VR0: -/VR9: Command Line Parameters      */
/*              - When BaseDir changes, change Windows CWD too  */
/*              - New Redaction Routine for PWD: EXE: CMD:      */
/* AChoir v1.6  - Add EXA: and EXB:  (Asyn & Background EXe)    */
/* AChoir v1.7  - Fix DSK: &DSK bug for Remote Collections      */
/*                 File not being properly closed causes loop.  */
/* AChoir v1.8  - Recognize Compressed Files, and allow them to */
/*                 be copied by the OS API to DeCompress them   */
/*                 The Flag for this behaviour is:              */
/*                 SET:NCP=OSCOPY or SET:NCP=RAWONLY            */
/*              - Also Added built in Support for WOW64 file    */
/*                 redirection of X86 binCopy of SYSTEM32       */
/*                 (sub) directories. This was needed for       */
/*                 switching from rawcopy to bincopy - plus its */
/*                 a good general feature anyway.               */
/* AChoir v1.9  - Recognize Compressed Size                     */
/* AChoir v1.9a - More Comressed Files Support                  */
/* AChoir v2.0  - Add LZNT1 Decompress Routine                  */
//*                Flag behaviors have changed:                 */
/*                 SET:NCP=NODCMP - NoDecompression             */
/*                 SET:NCP=DECOMP/RAWONLY - LZNT1 Decompress    */
/*                 SET:NCP=OSCOPY - Do OS/API copy on Decomp Err*/
/* AChoir v2.1  - Add App Compat Manifest - For 8.1 and above   */
/*                 comaptibility                                */
/*                Add new Conditional Logic on Windows Version  */
/*                VER:WinXP, WinXP64, Vista, Win7, Win8, Win8.1 */
/*                    Win10                                     */
/*                    Win2000, Win2003, Win2008, Win2008R2,     */
/*                    Win2012, Win2012R2, Win2016               */
/* AChoir v2.2  - Add Ver: Client, and Server checks            */
/* AChoir v2.3  - LZNT1 Bug fixes by Yogesh Katri               */
/* AChoir v2.4  - Update Offreg, and fix Edge Case of Short FN  */
/*                 without a Long FN in $MFT record.            */
/* AChoir v2.5  - Partial Back out of LZNT1 mod that negatively */
/*                 impacted $MFT Resident File extraction       */
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

/****************************************************************/
/* IMPORTANT NOTE : I could not have implemented the NTFS       */
/* LZNT1 Decode without the awesome LZNT1 code found in ReactOS */
/* hxxps://doxygen.reactos.org/d0/dd2/                          */
/*       sdk_2lib_2rtl_2compress_8c_source.html                 */
/*                                                              */
/* Much of the code in the Achoir LZNT1 decompressor function   */
/* is directly from this code.And I want to publicly thank      */
/*   them for making this amazing code available.               */
/****************************************************************/

#include "stdafx.h"

//Visual Leak Detector (In Debug)
//#include "VLD.h"

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

//Make new operator act like malloc
#include <new>

// #pragma comment (lib, "offreg.lib")
// #pragma comment(lib, "cmcfg32.lib")
#pragma comment(lib, "Advapi32.lib")

#include "accctrl.h"
#include "aclapi.h"
#include <sddl.h>

// Required for Net Share creation
#pragma comment(lib, "Netapi32.lib")
#include <lm.h>

// Required for Winsock 
#include <winsock.h>

// NTP Client Integer Types 
#include <stdint.h>
#define NTP_TIMESTAMP_DELTA 2208988800ull

// Headers for determining OS Version 
#include <VersionHelpers.h>

#define NUL '\0'
#define MaxArray 100
#define BUFSIZE 4096

char Version[10] = "v2.5\0";
char RunMode[10] = "Run\0";
int  iRanMode = 0;
int  iRunMode = 0;
int  iHtmMode = 0;
int  iChkYN = 0;
int  iChkRC = 0;
int  iIsAdmin = 0;
int  iExec = 0;
int  iIsCompressed = 0;
char cIsCompressed[15] = "\0";
int  setNCP = 2;  // 0=NODCMP, 1=DECOMP/RAWONLY, 2=OSCOPY (Default)

int  iNative = 0; // Are we Native 64Bit on 64Bit (Native = 1, NonNative = 0)
char sNative[10] = "\0";

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
size_t unIndent(char *SqString);
long twoSplit(char *SpString);
char *stristr(const char *String, const char *Pattern);
int  FileMD5(char *MD5FileName);
int  MemAllocErr(char *ErrType);
int  binCopy(char *FrmFile, char *TooFile, int binLog);
int  lznCopy(char *FrmFile, char *TooFile, ULONG TooSize);
void Time_tToFileTime(time_t InTimeT, int whichTime);
long varConvert(char *inVarRec);
long consInput(char *consString, int conLog, int conHide);
long mapsDrive(char *mapString, int mapLog);
long netLocalShare(char *netServer, char *netSharePath, char *netShareName, int shrLog);
long netShareDel(char *netShareName, int shrLog);
int PreIndex();
BOOL IsUserAdmin(VOID);
void showTime(char *showText);
void USB_Protect(DWORD USBOnOff);
void cleanUp_Exit(int exitRC);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
char * convert_sid_to_string_sid(const PSID psid, char *sid_str);
void getCaseInfo(int SayOrGet);
int ntpGetTime(char* ntpServer);
size_t Redactor(char *inRedact, char *outRedact);
BOOL CompareWindowsVersion(DWORD dwMajorVersion, DWORD dwMinorVersion);


// Variables to create a share
int  iGoodShr = 0;
NET_API_STATUS netShrRC;
SHARE_INFO_2 netShr;
DWORD netShrErr = 0;

// Routines For Raw NTFS Access
ULONG RunLength(PUCHAR run);
LONGLONG RunLCN(PUCHAR run);
ULONGLONG RunCount(PUCHAR run);
BOOL FindRun(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, PULONGLONG lcn, PULONGLONG count);
PATTRIBUTE FindAttributeX(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, PWSTR name, int attrNum);
VOID FixupUpdateSequenceArray(PFILE_RECORD_HEADER file);
VOID ReadSectorX(ULONGLONG sector, PVOID buffer);
VOID ReadSectorToMem(ULONGLONG sector, ULONG count, PVOID buffer);
VOID ReadSectorToDisk(ULONGLONG sector, ULONG count, PVOID buffer);
VOID ReadLCN(ULONGLONG lcn, ULONG count, PVOID buffer);
VOID ReadExternalAttribute(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, ULONG count, PVOID buffer);
ULONG AttributeLength(PATTRIBUTE attr);
ULONG AttributeLengthAllocated(PATTRIBUTE attr);
ULONG AttributeLengthDataSize(PATTRIBUTE attr);
ULONG AttributeLengthCompressed(PATTRIBUTE attr);
VOID ReadAttribute(PATTRIBUTE attr, PVOID buffer);
VOID ReadVCN(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, ULONGLONG vcn, ULONG count, PVOID buffer);
VOID ReadFileRecord(ULONG index, PFILE_RECORD_HEADER file);
VOID LoadMFT();
VOID UnloadMFT();
int FindActive();
int rawCopy(char *FrmFile, char *TooFile, int binLog);
int DumpDataII(ULONG index, CHAR* filename, CHAR* outdir, FILETIME ToCreTime, FILETIME ToModTime, FILETIME ToAccTime, int binLog, int Append);
//int spinOnChange(char* SpinFileName);


// Global Variables For Raw NTFS Access
ULONG BytesPerFileRecord;
HANDLE hVolume;
BOOT_BLOCK bootb;
PFILE_RECORD_HEADER MFT;
int readRetcd = 1; // Global read Return Code - When something goes real bad.
char Str_Temp[1024] = "\0";
char Str_Short[256] = "\0";
CHAR driveLetter[] = "C\0\0\0\0";
CHAR rootDrive[] = "C:\\\0\0\0";

char SidString[256];
ULONGLONG File_CreDate, File_AccDate, File_ModDate;
int gotOwner = 0;

// Static Security Descriptor Buffer
PSECURITY_DESCRIPTOR SecDesc[255];

// Dynamic Security Descriptor Buffer
//PSECURITY_DESCRIPTOR SecDesc = NULL;

//Start with Max Memory Alloc = 250MB
ULONG maxMemBytes = 262144000;
int maxMemExceed = 0;
int useDiskOrMem = 0; // 0 is Memory, 1 is Disk

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
FILE* DskHndl;
FILE* MD5Hndl;
FILE* IniHndl;
FILE* WGetHndl;
FILE* HtmHndl;

char LogFile[1024] = "C:\\AChoir\\AChoir.exe\0";
char CpyFile[1024] = "C:\\AChoir\\AChoir.exe\0";
char ChkFile[1024] = "C:\\AChoir\\AChoir.exe\0";
char MD5File[1024] = "C:\\AChoir\\Hashes.txt\0";
char ForFile[1024] = "C:\\AChoir\\ForFiles\0";
char ForDisk[1024] = "C:\\AChoir\\ForDisks\0";
char LstFile[1024] = "C:\\AChoir\\LstFiles\0";
char IniFile[1024] = "C:\\AChoir\\AChoir.ACQ\0";
char HtmFile[1024] = "C:\\AChoir\\Index.html\0";
char CmdExe[1024] = "C:\\AChoir\\cmd.exe\0";
char CmdHash[35] = "d05c529f0eebb6aaf10cbdecde14d310\0";
char TempDir[1024] = "C:\\AChoir\0";
char BaseDir[1024] = "C:\\AChoir\0";
char CurrDir[1024] = "\0";
char CurrWorkDir[1024] = "\0";
char CurrFil[255] = "AChoir.dat\0";
char DiskDrive[10] = "C:\0\0\0";
char MapDrive[10] = "C:\0\0\0";
char *WinRoot = "C:\\Windows";
char *Procesr = "AMD64";
char *TempVar = "C:\\Windows\\Temp";
char *ProgVar = "C:\\Program Files";
char CrLf[3] = {0x0D, 0x0A, 0x00};

int  iLogOpen = 0 ;

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

int  TermRC = 0;
int  LastRC = 0;
int  ChkRC = 0;
char *ExePtr, *ParmPtr, *CopyPtr;


char volType[10] = " \0";
char RootDir[FILENAME_MAX] = " \0";
char FullFName[FILENAME_MAX];
char ForFName[FILENAME_MAX];

DWORD netRC = NO_ERROR;
NETRESOURCE netRes = { 0 };
TCHAR szConnection[MAX_PATH];
DWORD ConnectSize = MAX_PATH, ConnectResult, Flags = (CONNECT_INTERACTIVE | CONNECT_REDIRECT);

size_t iPrm1, iPrm2, iPrm3;
char *iPtr1, *iPtr2, *iPtr3;

struct _stat Frmstat;
struct _stat Toostat;
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
HKEY  hKCU = HKEY_CURRENT_USER;
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
int  iSleep;

int  iXitCmd = 0;
char XitCmd[4096];

//Track Current File Information across Routines
int fileIsFrag;
ULONG totbytes, totdata;
ULONG maxFileSize, leftFileSize;
ULONG maxDataSize, leftDataSize;
int LCNType = 0;  // 0 for Attributes, 1 for Files (used for tracking leftFileSize)
int iDepth = 0;   // Sanity Check for Recursion Loops

//File Signature Copy Table & Vars
int  iSigCount = 0;
int  iSigTMax = 100;
int  iSigSize = 33; // One Extra byte for null terminator
int  iTypSize = 11; // One Extra byte for null terminator
char *SigTabl;
char *TypTabl;
int  *SizTabl;
char * equDelim ;
char tmpSig[255];
int  tmpSize;
int  iNCS = 0;
int  iNCSFound = 0; // 0==Found, 1==Not
int  iCPS = 0;
int  iCPSFound = 0; // 0==Found, 1==Not

PUCHAR ClustZero; // First Cluster buffer

// Console Hande for Hide, Show
HWND conHndl;
int  iConMode = 1 ;

// Console Input instead of File
int consOrFile = 0;

// Console Coloring
void consPrefix(char *consText, int consColor);
HANDLE  hConsole;
char    consTemp[10] ; 
int     consBlu = 11 ;
int     consGre = 10 ;
int     consRed = 12 ;
int     consYel = 14 ;
int     consWhi = 15 ;

// Case Information (ONLY ONCE!)
// 0 = Not Entered, 1 = Entered, 2 = /CSE Arg
int  iCase = 0 ;
char caseNumbr[255] ; 
char evidNumbr[255] ; 
char caseDescr[255] ; 
char caseExmnr[255] ; 


// DSK Variables
int  dskNum ;
int  dskTyp ;
int  DskMe ;
char dskNam[10] = "A:\\\0";
char Dskrec[10] = "A:\\\0";
char Alphabet[30] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\0";


// NTP Variables
char ntpFQDN[255] = "\0";
char ntpDateTime[25] = "01/01/0001 - 01:01:01\0";


// Template for padding
template <class T1, class T2> inline T1* Padd(T1* p, T2 n)
{
  return (T1*)((char *)p + n);
}


//Start Testing Variables
ULONG lst_cur, lst_end, tot_byt_src, tot_byt_dst;
//End Testing Varaibles

//Global Variables for lznCopy
ULONG last_rawdLen ;
char  last_Fname[2048] = "\0";

//#define STATUS_ACCESS_VIOLATION 0xC0000005
#define STATUS_BAD_COMPRESSION_BUFFER 0xC0000242
#define STATUS_SUCCESS 0x00000000

//lznCopy - Routines Definitions
static PUCHAR lznt1_decompress_chunk (UCHAR * dst, ULONG dst_size, UCHAR * src, ULONG src_size);
static NTSTATUS lznt1_decompress ( UCHAR * dst, ULONG dst_size, UCHAR * src, ULONG src_size, ULONG offset, ULONG * final_size, UCHAR * workspace);

//Windows Version
char descrWinVer[50] = "Unknown\0";
char shortWinVer[15] = "Win\0";
int  iIsServer = 0;

//Offline Registry 
DWORD ORRetcd ;

int main(int argc, char *argv[])
{
  int i;
  int iPtr;
  size_t oPtr, ArnLen, ArnPtr;
  int RunMe, ForMe, LstMe, Looper, LoopNum ;

  char Tmprec[2048];
  char Filrec[2048];
  char Lstrec[2048];
  char Cpyrec[4096];
  char Exerec[4096];
  char Cmprec[4096];
  char Arnrec[2048];
  char Shrrec[1024];
  char Redrec[1024];

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
  /* Get the Consolewindow Handle - Since we have Focus           */
  /****************************************************************/
  conHndl = GetConsoleWindow();


  /****************************************************************/
  /* Volume Information Variables                                 */
  /****************************************************************/
  TCHAR volumeName[MAX_PATH + 1] = { 0 };
  TCHAR fileSystemName[MAX_PATH + 1] = { 0 };
  DWORD serialNumber = 0;
  DWORD maxComponentLen = 0;
  DWORD fileSystemFlags = 0;
  int isNTFS = 0;
  PUCHAR bufT;

  //Set Console Handle (For Pretty Colors)
  hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

  /****************************************************************/
  /* Set Defaults                                                 */
  /****************************************************************/
  iIsAdmin = 0;
  iXitCmd = 0;
  iLogOpen = 0;

  memset(CurrDir, 0, 1024);
  memset(CurrWorkDir, 0, 1024);
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
  memset(ntpFQDN, 0, 255);

  memset(VarArray, 0, 2560);
  memset(cIsCompressed,0, 15);

  strncpy(inFnam, "AChoir.ACQ\0", 11);


  /****************************************************************/
  /* What Directory are we in?                                    */
  /****************************************************************/
  getcwd(BaseDir, 1000);      // Just The Drive
  getcwd(CurrWorkDir, 1000);  // Working Directory

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
  /* Allocate File Signature and Type Tables.                     */
  /****************************************************************/
  iSigCount = 0;

  SigTabl  = (char *) malloc(iSigTMax * iSigSize)  ;
  if(SigTabl == NULL) 
   MemAllocErr("File Signature Table") ;

  TypTabl  = (char *) malloc(iSigTMax * iTypSize)  ;
  if(TypTabl == NULL) 
   MemAllocErr("File Type Table") ;

  SizTabl = (int *) malloc(iSigTMax * sizeof(int)) ;
  if(SizTabl == NULL) 
   MemAllocErr("File Signature Size Table") ;


  /****************************************************************/
  /* Build the &ACQ Incident Number                               */
  /****************************************************************/
  if (GetComputerName(cName, &len) != 0)
    sprintf(ACQName, "ACQ-IR-%s-%04d%02d%02d-%02d%02d\0", cName, iYYYY, iMonth, iDay, iHour, iMin);
  else
    sprintf(ACQName, "ACQ-IR-%04d%02d%02d-%02d%02d\0", iYYYY, iMonth, iDay, iHour, iMin);


  /****************************************************************/
  /* Default Case Settings                                        */
  /****************************************************************/
  memset(caseNumbr, 0, 255) ;
  memset(evidNumbr, 0, 255) ;
  memset(caseDescr, 0, 255) ;
  memset(caseExmnr, 0, 255) ;
  strncpy(caseNumbr, ACQName, 255) ;
  strncpy(evidNumbr, "001", 3) ;
  sprintf(caseDescr, "AChoir Live Acquisition: %s\0", ACQName) ;
  strncpy(caseExmnr, "Unknown", 7) ;

  
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
      printf("\nAChoir ver: %s, Argument/Options:\n", Version);

      SetConsoleTextAttribute(hConsole, consGre);
      consPrefix(" /Help ", consGre);
      printf("- This Description\n");

      consPrefix(" /BLD ", consGre);
      printf("- Run the Build.ACQ Script (Build the AChoir Toolkit)\n");

      consPrefix(" /MNU ", consGre);
      printf("- Run the Menu.ACQ Script (A Simple AChoir Menu)\n");

      consPrefix(" /RUN ", consGre);
      printf("- Run the AChoir.ACQ Script to do a Live Acquisition\n");

      consPrefix(" /DRV:<x:> ", consGre);
      printf("- Set the &DRV parameter\n");

      consPrefix(" /USR:<UserID> ", consGre);
      printf("- User to Map to Remote Server\n");

      consPrefix(" /PWD:<Password> ", consGre);
      printf("- Password to Map to Remote Server\n");

      consPrefix(" /MAP:<Server\\Share> ", consGre);
      printf("- Map to a Remote Server\n");

      consPrefix(" /INI:<File Name> ", consGre);
      printf("- Run the <File Name> script instead of AChoir.ACQ\n");

      consPrefix(" /CSE ", consGre);
      printf("- Ask For Case, Evidence, and Examiner Information\n");

      consPrefix(" /CON ", consGre);
      printf("- Run with Interactive Console Input (Same as /Ini:Console)\n");
      SetConsoleTextAttribute(hConsole, consWhi);

      exit(0);
    }
    else
    if ((strnicmp(argv[i], "/CSE", 4) == 0) && (strlen(argv[i]) == 4))
    {
      iCase = 2;
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

        consPrefix("[+] ", consGre);
        printf("Disk Drive Set: %s\n", DiskDrive);
      }
      else
      {
        consPrefix("[!] ", consRed);
        printf("Invalid Disk Drive Setting: %s\n", argv[i] + 5);
      }
    }
    else
    if (strnicmp(argv[i], "/CON", 4) == 0)
    {
      consOrFile = 1;
      strncpy(RunMode, "Con\0", 4);
      strncpy(inFnam, "Console\0", 8);
      iRunMode = 1;
    }
    else
    if ((strnicmp(argv[i], "/INI:", 5) == 0) && (strlen(argv[i]) > 5))
    {
      //Check if Input is Console
      if (strnicmp(argv[i], "/INI:Console", 12) == 0)
      {
        consOrFile = 1;
        strncpy(RunMode, "Con\0", 4);
        strncpy(inFnam, argv[i] + 5, 254);
        iRunMode = 1;
      }
      else
      if (strlen(argv[i]) < 254)
      {
        strncpy(RunMode, "Ini\0", 4);
        strncpy(inFnam, argv[i] + 5, 254);

        // Initially Set iRunmode to 2 (in case we are running remote)
        // Avoids Creating a Local BACQDIR
        iRunMode = 2;
      }
      else
      {
        consPrefix("[!] ", consRed);
        printf("/INI:  Too Long (Greater than 254 chars)\n");
      }
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
      {
         consPrefix("[!] ", consRed);
         printf("/MAP:  Too Long (Greater than 254 chars)\n");
      }
    }
    else
    if (strnicmp(argv[i], "/USR:", 5) == 0)
    {
      if (argv[i][5] =='?')
      {
        consPrefix("[?] ", consYel);
        consInput("Enter Share Mapping UserId> ", 0, 0);
        memset(inUser, 0, 255);
        strncpy(inUser, Conrec, 254);
      }
      else
      if (strlen(argv[i]) < 254)
      {
        memset(inUser, 0, 255);
        strncpy(inUser, argv[i] + 5, 254);
      }
      else
      {
         consPrefix("[!] ", consRed);
         printf("/USR:  Too Long (Greater than 254 chars)\n");
      }
    }
    else
    if (strnicmp(argv[i], "/PWD:", 5) == 0)
    {
      if (argv[i][5] =='?')
      {
        consPrefix("[?] ", consYel);
        consInput("Enter Share Mapping Password> ", 0, 1);
        memset(inPass, 0, 255);
        strncpy(inPass, Conrec, 254);
      }
      else
      if (strlen(argv[i]) < 254)
      {
        memset(inPass, 0, 255);
        strncpy(inPass, argv[i] + 5, 254);
      }
      else
      {
         consPrefix("[!] ", consRed);
         printf("/PWD:  Too Long (Greater than 254 chars)\n");
      }
    }
    else
    if ((strnicmp(argv[i], "/VR", 3) == 0) && (argv[i][4] == ':'))
    {
      /**********************************************************/
      /* Allow Varibles VR0 - VR9 on Command Line. This should  */
      /*  make seting up menus a little easier                  */
      /**********************************************************/
      switch (argv[i][3])
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
        consPrefix("[!] ", consRed);
        printf("Invalid Variable: %.4s\n", argv[i]);
      }
      else
      {
        strncpy(VarArray+iVar, argv[i]+5, 255);
      }
    }
    else
    {
      consPrefix("[!] ", consRed);
      printf("Bad Argument: %s\n", argv[i]);
    }

    fflush(stdout); //More PSExec Friendly

  }


  /****************************************************************/
  /* Should we Map a Drive First?  If yes, set the BaseDir and    */
  /*  DLL Directory too.                                          */
  /****************************************************************/
  if (iArgsMap == 1)
  {
    mapsDrive(inMapp, 0);
    strncpy(BaseDir, MapDrive, 4);

    // Reset The WorkingDirectory to the Mapped Drive
    sprintf(CurrWorkDir, "%s\\\0", BaseDir);
    _chdir(CurrWorkDir); 

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
  sprintf(ForFile, "%s\\%s\\Cache\\ForFiles\0", BaseDir, ACQName);
  sprintf(ForDisk, "%s\\%s\\Cache\\ForDisks\0", BaseDir, ACQName);
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
    consPrefix("[!] ", consRed);
    printf("Could not Open Log File.\n");
    //printf("%s\n", LogFile);
    exit(3);
  }

  iLogOpen = 1;

  consPrefix("[+] ", consGre);
  printf("AChoir ver: %s, Mode: %s\n", Version, RunMode);
  fprintf(LogHndl, "[+] AChoir ver: %s, Mode: %s\n", Version, RunMode);

  showTime("Start Acquisition");
  fflush(stdout); //More PSExec Friendly


  /****************************************************************/
  /* Display Windows Version - This Klugy API requires checking   */
  /*  all versions, since thelogic is Equals or Greater Than      */
  /****************************************************************/
  if(IsWindowsServer())
   iIsServer = 1 ;
  else
   iIsServer = 0;

  memset(descrWinVer, 0, 50);
  memset(shortWinVer, 0, 15);
  if(CompareWindowsVersion(10, 0))
  {
    // Windows 10 or Server 2016
    if(iIsServer == 0)
    {
      strncpy(shortWinVer, "Win10\0\0\0", 8);
      strncpy(descrWinVer, "Windows 10 (10.0)\0\0\0", 20);
    }
    else
    {
      strncpy(shortWinVer, "Win2016\0\0\0", 10);
      strncpy(descrWinVer, "Server 2016 (10.0)\0\0\0", 21);
    }
  }
  else
  if(CompareWindowsVersion(6, 3))
  {
    // Windows 8.1 or Server 2012R2
    if(iIsServer == 0)
    {
      strncpy(shortWinVer, "Win8.1\0\0\0", 9);
      strncpy(descrWinVer, "Windows 8.1 (6.3)\0\0\0", 20);
    }
    else
    {
      strncpy(shortWinVer, "Win2012R2\0\0\0", 12);
      strncpy(descrWinVer, "Server 2012R2 (6.3)\0\0\0", 22);
    }
  }
  else
  if(CompareWindowsVersion(6, 2))
  {
    // Windows 8 or Server 2012
    if(iIsServer == 0)
    {
      strncpy(shortWinVer, "Win8\0\0\0", 7);
      strncpy(descrWinVer, "Windows 8 (6.2)\0\0\0", 13);
    }
    else
    {
      strncpy(shortWinVer, "Win2012\0\0\0", 10);
      strncpy(descrWinVer, "Server 2012 (6.2)\0\0\0", 20);
    }
  }
  else
  if(CompareWindowsVersion(6, 1))
  {
    // Windows 7 or Server 2008R2
    if(iIsServer == 0)
    {
      strncpy(shortWinVer, "Win7\0\0\0", 7);
      strncpy(descrWinVer, "Windows 7 (6.1)\0\0\0", 18);
    }
    else
    {
      strncpy(shortWinVer, "Win208R2\0\0\0", 11);
      strncpy(descrWinVer, "Server 2008R2 (6.1)\0\0\0", 22);
    }
  }
  else
  if(CompareWindowsVersion(6, 0))
  {
    // Windows Vista or Server 2008
    if(iIsServer == 0)
    {
      strncpy(shortWinVer, "Vista\0\0\0", 8);
      strncpy(descrWinVer, "Windows Vista (6.0)\0\0\0", 22);
    }
    else
    {
      strncpy(shortWinVer, "Win2008\0\0\0", 10);
      strncpy(descrWinVer, "Server 2008 (6.0)\0\0\0", 20);
    }
  }
  else
  if(CompareWindowsVersion(5, 2))
  {
    // Windows XP 64Bit or Server 2003(R2)
    if(iIsServer == 0)
    {
      strncpy(shortWinVer, "WinXP64\0\0\0", 10);
      strncpy(descrWinVer, "Windows XP64 (5.2)\0\0\0", 21);
    }
    else
    {
      strncpy(shortWinVer, "Win2003\0\0\0", 10);
      strncpy(descrWinVer, "Server 2003/2003R2 (5.2)\0\0\0", 27);
    }
  }
  else
  if(CompareWindowsVersion(5, 1))
  {
    // Windows XP
    strncpy(shortWinVer, "WinXP\0\0\0", 8);
    strncpy(descrWinVer, "Windows XP (5.1)\0\0\0", 19);
  }
  else
  if(CompareWindowsVersion(5, 0))
  {
    // Windows 2000
    strncpy(shortWinVer, "Win2000\0\0\0", 10);
    strncpy(descrWinVer, "Windows 2000 (5.1)\0\0\0", 21);
  }

  consPrefix("[+] ", consGre);
  printf("Detected Windows Ver: %s\n", descrWinVer);
  fprintf(LogHndl, "[+] Detected Windows Ver: %s\n", descrWinVer);


  /****************************************************************/
  /* Are we running Non-Native (Sysnative vs. System32)           */
  /****************************************************************/
  memset(TempDir, 0, 1024);
  sprintf(TempDir, "%s\\Sysnative\0", WinRoot);

  if (access(TempDir, 0) == 0)
  {
    strncpy (sNative, "NON-\0", 5);
    iNative = 0;
  }
  else
  {
    strncpy (sNative, "\0\0\0\0\0", 5);
    iNative = 1;
  }
  memset(TempDir, 0, 1024);



  /****************************************************************/
  /* Check If We are an Admin                                     */
  /****************************************************************/
  if (IsUserAdmin() == TRUE)
  {
    iIsAdmin = 1;

    consPrefix("[+] ", consGre);
    printf("Running As Admin, %sNative\n", sNative);
    fprintf(LogHndl, "[+] Running As Admin, %sNative\n", sNative);
  }
  else
  {
    consPrefix("[+] ", consGre);
    printf("Running As NON-Admin, %sNative\n", sNative);
    fprintf(LogHndl, "[+] Running As NON-Admin, %sNative\n", sNative);
    iIsAdmin = 0;
  }
  fflush(stdout); //More PSExec Friendly


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

  consPrefix("[+] ", consGre);
  printf("Privileges(%d):", PrivSet);
  fprintf(LogHndl, "[+] Privileges(%d):", PrivSet);

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
  fflush(stdout); //More PSExec Friendly


  fprintf(LogHndl, "[+] Directory Has Been Set To: %s\\%s\n", BaseDir, CurrDir);
  fprintf(LogHndl, "[+] Input Script Set:\n     %s\n\n", IniFile);


  /****************************************************************/
  /* If iRunMode=1 Create the BACQDir - Base Acquisition Dir      */
  /****************************************************************/
  if (iRunMode == 1)
  {
    // Have we created the Base Acquisition Directory Yet?
    fprintf(LogHndl, "[+] Creating Base Acquisition Directory: %s\n", BACQDir);

    consPrefix("[+] ", consGre);
    printf("Creating Base Acquisition Directory: %s\n", BACQDir);

    if (access(BACQDir, 0) != 0)
    {
      mkdir(BACQDir);
      mkdir(CachDir);
      PreIndex();
    }

    fflush(stdout); //More PSExec Friendly

  }


  // Should We Gather Case Information (/CSE)
  if(iCase == 2)
   getCaseInfo(1);


  /****************************************************************/
  /* Open The Input Script File                                   */
  /****************************************************************/
  memset(Inrec, 0, 4096);
  memset(Tmprec, 0, 2048);

  if(consOrFile == 1)
  {
    consPrefix("[+] ", consGre);
    printf("Switching to Console Input.\n");
    consPrefix(">>> ", consGre);

    fprintf(LogHndl, "[+] Switching to Console Input.\n");

    IniHndl = stdin;
  }
  else
   IniHndl = fopen(IniFile, "r");

  fflush(stdout); //More PSExec Friendly

  if (IniHndl != NULL)
  {
    RunMe = 0;  // Conditional run Script default is yes

    while (fgets(Tmprec, 1000, IniHndl))
    {
      //Remove any preceding blanks
      unIndent(Tmprec);

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
        if (strnicmp(Tmprec, "VER:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "CKY:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "CKN:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "EQU:", 4) == 0)
          RunMe++;
        else
        if (strnicmp(Tmprec, "NEQ:", 4) == 0)
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
            consPrefix("[!] ", consRed);
            printf("&FOR Directory has not been set with the FOR: command.  Ignoring &FOR Loop...\n");

            fprintf(LogHndl, "[!] &FOR Directory has not been set with the FOR: command.  Ignoring &FOR Loop...\n");
            Looper = 0;

            fflush(stdout); //More PSExec Friendly
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
            consPrefix("[!] ", consRed);
            printf("&LST File was not found (LST: not set): %s\n", LstFile);

            fprintf(LogHndl, "[!] &LST File not found (LST: not set): %s\n", LstFile);
            Looper = 0;
          }

          fflush(stdout); //More PSExec Friendly

        }
        else
          LstMe = 0;


        /****************************************************************/
        /* DskFiles Looper Setup                                        */
        /****************************************************************/
        if (stristr(Tmprec, "&DSK") > 0)
        {
          DskMe = 1;
          memset(Dskrec, 0, 10);

          DskHndl = fopen(ForDisk, "r");

          if (DskHndl == NULL)
          {
            consPrefix("[!] ", consRed);
            printf("&DSK Listing was not found (DSK: not set): %s\n", ForDisk);

            fprintf(LogHndl, "[!] &DSK Listing not found (DSK: not set): %s\n", ForDisk);
            Looper = 0;
          }

          fflush(stdout); //More PSExec Friendly

        }
        else
          DskMe = 0;
        

        /****************************************************************/
        /* Loop (FOR: and LST:) until Looper = 1                        */
        /****************************************************************/
        LoopNum = 0;
        while (Looper == 1)
        {
          if ((ForMe == 0) && (LstMe == 0) && (DskMe == 0))
            Looper = 0;
          else
          if ((ForMe == 1) && (LstMe == 0) && (DskMe == 0))
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
          if ((ForMe == 0) && (LstMe == 1) && (DskMe == 0))
          {
            if (fgets(Lstrec, 1000, LstHndl))
            {
              Looper = 1;
              LoopNum++;

              strtok(Lstrec, "\n");
              strtok(Lstrec, "\r");
            }
            else
              break;
          }
          else
          if ((ForMe == 0) && (LstMe == 0) && (DskMe == 1))
          {
            if (fgets(Dskrec, 10, DskHndl))
            {
              Looper = 1;
              LoopNum++;

              strtok(Dskrec, "\n");
              strtok(Dskrec, "\r");
            }
            else
              break;
          }
          else
          {
            Looper = 0;

            fprintf(LogHndl, "[!] AChoir does not yet support Nested Looping (&LST + &FOR)\n     > %s\n", Tmprec);

            consPrefix("[!] ", consRed);
            printf("AChoir does not yet support Nested Looping (&LST + &FOR)\n     > %s\n", Tmprec);

            strncpy(Tmprec, "***: Command Bypassed\0\0\0\0\0\0\0\0\0", 25);

            fflush(stdout); //More PSExec Friendly

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
            if (strnicmp(o32VarRec + iPtr, "&Ntp", 4) == 0)
            {
              // Full Date and Time - mm/dd/yyyy - hh:mm:ss
              if(strlen(ntpFQDN) > 0)
              {
                memset(ntpDateTime, 0, 25);
                ntpGetTime(ntpFQDN);
                
                sprintf(Inrec + oPtr, "%s", ntpDateTime);
                oPtr = strlen(Inrec);
              }
              else
              {
                consPrefix("\n[!] ", consRed);
                fprintf(LogHndl, "[!] NTP Server FQDN has not been set, Bypassing NTP.\n");
                printf( "NTP Server FQDN has not been set, Bypassing NTP..\n" );
              }

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
            if (strnicmp(o32VarRec + iPtr, "&Dsk", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s", Dskrec);
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
            if (strnicmp(o32VarRec + iPtr, "&Vck", 4) == 0)
            {
              sprintf(Inrec + oPtr, "%s", volType);
              oPtr = strlen(Inrec);
              iPtr += 3;
            }
            else
            if ((o32VarRec[iPtr] == '*') && ((strnicmp(o32VarRec, "NCP:", 4) == 0) || (strnicmp(o32VarRec, "NCS:", 4) == 0)))
            {
              //Special Case to replace WildCard for NCP: with SQLite Wildcards (%)
              sprintf(Inrec + oPtr, "%%\0");
              oPtr = strlen(Inrec);
            }
            else
            if ((o32VarRec[iPtr] == '?') && ((strnicmp(o32VarRec, "NCP:", 4) == 0) || (strnicmp(o32VarRec, "NCS:", 4) == 0)))
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
                fprintf(LogHndl, "[!] Invalid Variable: %.4s\n", o32VarRec + iPtr);

                consPrefix("[!] ", consRed);
                printf("Invalid Variable: %.4s\n", o32VarRec + iPtr);

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

            fflush(stdout); //More PSExec Friendly

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
            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);
              fprintf(LogHndl, "[*] Jumping Does not make sense in Interactive Mode.  Ignoring...\n");
              printf("Jumping Does not make sense in Interactive Mode.  Ignoring...\n");
            }
            else
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
          }
          else
          if (strnicmp(Inrec, "Cse:", 4) == 0)
          {
            /****************************************************************/
            /* Get Case Information                                         */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            if (strnicmp(Inrec+4, "Get", 3) == 0)
             getCaseInfo(1);
            else
             getCaseInfo(0);
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
              // Set iRunMode=1 to be sure we post-process the Acquired Artifacts
              // (In case we had not set it originally due to remote BACQDIR)
              iRunMode = 1;

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
                //Check to see if it is an append or new &Acq
                //Dont add // if it's new!
                if(strlen(ACQDir) > 0)
                 strcat(ACQDir, "\\\0");

                strcat(ACQDir, Inrec + 4);
                sprintf(TempDir, "%s\\%s\0", BACQDir, ACQDir);
              }
            }

            if (access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "SET: Creating Acquisition Sub-Directory: %s\n", ACQDir);

              consPrefix("SET: ", consBlu);
              printf("Creating Acquisition Sub-Directory: %s\n", ACQDir);
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

            fprintf(LogHndl, "SET: Acquisition Sub-Directory Has Been Set To: %s\n", ACQDir);
            consPrefix("SET: ", consBlu);
            printf("Acquisition Sub-Directory Has Been Set To: %s\n", ACQDir);

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
                if(strlen(CurrDir) > 0 )
                 strcat(CurrDir, "\\\0"); // Only add backslash for appended Directories

                strcat(CurrDir, Inrec + 4);
                sprintf(TempDir, "%s\\%s\0", BaseDir, CurrDir);
              }
            }


            if (access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "SET: Creating Directory: %s\n", CurrDir);
              consPrefix("SET: ", consBlu);
              printf("Creating Directory: %s\n", CurrDir);
              mkdir(TempDir);
            }

            fprintf(LogHndl, "SET: Directory Has Been Set To: %s\n", CurrDir);
            consPrefix("SET: ", consBlu);
            printf("Directory Has Been Set To: %s\n", CurrDir);

            // Reset The WorkingDirectory to the new Directory
            sprintf(CurrWorkDir, "%s\\%s\0", BaseDir, CurrDir);
            _chdir(CurrWorkDir); 
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
              fprintf(LogHndl, "SET: Creating Directory: %s\n", CurrDir);
              consPrefix("SET: ", consBlu);
              printf("Creating Directory: %s\n", CurrDir);
              mkdir(TempDir);
            }

            fprintf(LogHndl, "SET: File Has Been Set To: %s\n", CurrFil);
            consPrefix("SET: ", consBlu);
            printf("File Has Been Set To: %s\n", CurrFil);

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
              fprintf(LogHndl, "[!] Invalid Variable Define Action: %.4s\n", Inrec);

              consPrefix("[!] ", consRed);
              printf("Invalid Variable Define Action: %.4s\n", Inrec);
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
              consPrefix("SET: ", consBlu);
              printf("Disk Drive Set: %s\n", DiskDrive);
            }
            else
            {
              consPrefix("[!] ", consRed);
              printf("Invalid Disk Drive Setting: %s\n", Inrec + 4);
            }
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

            if(strnicmp(IniFile, "Console", 7) == 0)
            {
              // If we are not ALREADY in Interactive Mode, Switch
              if(consOrFile == 0)
              {
                strncpy(RunMode, "Con\0", 4);
                strncpy(inFnam, "Console\0", 8);

                iRunMode = 1;
                consOrFile = 1;
                strncpy(inFnam, "Console\0", 8);

                consPrefix("[+] ", consGre);
                printf("Switching to Console (Interactive) Mode\n");
                fprintf(LogHndl, "[+] Switching to Console (Interactive) Mode.\n");

                fclose(IniHndl);
                IniHndl = stdin;
              }
            }
            else
            if (access(IniFile, 0) != 0)
            {
              fprintf(LogHndl, "[!] Requested INI File Not Found: %s - Ignored.\n", Inrec + 4);

              consPrefix("[!] ", consRed);
              printf("Requested INI File Not Found: %s - Ignored.\n", Inrec + 4);
            }
            else
            {
              fprintf(LogHndl, "[+] Switching to INI File: %s\n", Inrec + 4);

              consPrefix("[+] ", consGre);
              printf("Switching to INI File: %s\n", Inrec + 4);

              // Only close the handle if its not Console. If it is Console Set it back to File
              if(consOrFile == 0)
               fclose(IniHndl);
              else
               consOrFile = 0;

              IniHndl = fopen(IniFile, "r");

              if (IniHndl != NULL)
                RunMe = 0;  // Conditional run Script default is yes
              else
              {
                fprintf(LogHndl, "[!] Could Not Open INI File: %s - Exiting.\n", Inrec + 4);
 
                consPrefix("[!] ", consRed);
                printf("Could Not Open INI File: %s - Exiting.\n", Inrec + 4);
                cleanUp_Exit(3);
                exit (3);
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
              consPrefix("[+] ", consGre);
              printf("Running As Admin\n");
              fprintf(LogHndl, "[+] Running As Admin\n");
            }
            else
            {
              consPrefix("[+] ", consGre);
              printf("Running As NON-Admin\n");
              fprintf(LogHndl, "[+] Running As NON-Admin\n");
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
              consPrefix("[+] ", consGre);
              printf("Running As Admin - Continuing....\n");
              fprintf(LogHndl, "[+] Running As Admin - Continuing...\n");
            }
            else
            {
              consPrefix("[!] ", consRed);
              printf("Script IS NOT Running As Admin!\n     Please Re-Run As Admin!\n     Exiting.\n");
              fprintf(LogHndl, "[!] Running As NON-Admin\n     Please Re-Run as Admin!\n     Exiting.");
              cleanUp_Exit(3);
              exit (3);
            }
          }
          else
          if (strnicmp(Inrec, "Ntp:", 4) == 0)
          {
            /****************************************************************/
            /* Save NTP FQDN                                                */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");
            
            memset(ntpFQDN, 0, 255);
            sprintf(ntpFQDN, "%s\0", Inrec + 4);

            consPrefix("[+] ", consGre);
            printf("NTP Server FQDN Set to: %s\n", ntpFQDN);
            fprintf(LogHndl, "NTP Server FQDN Set to: %s\n", ntpFQDN);
          }
          else
          if (strnicmp(Inrec, "Con:Hide", 8) == 0)
          {
            /****************************************************************/
            /* Free The Console and Go Dark                                 */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            iConMode = 0;
            ShowWindow(conHndl, SW_MINIMIZE);
            ShowWindow(conHndl, SW_HIDE);

          }
          else
          if (strnicmp(Inrec, "Con:Show", 8) == 0)
          {
            /****************************************************************/
            /* Free The Console and Go Dark                                 */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            ShowWindow(conHndl, SW_SHOW);
            ShowWindow(conHndl, SW_RESTORE);

          }
          else
          if (strnicmp(Inrec, "Slp:", 4) == 0)
          {
            /****************************************************************/
            /* Sleep for number of Seconds                                  */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            iSleep = atoi(Inrec + 4);
            Sleep(iSleep*1000);
          }
          else
          if (strnicmp(Inrec, "Inp:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            consInput(Inrec + 4, 1, 0);
            strncpy(Inprec, Conrec, 254);
          }
          else
          if (strnicmp(Inrec, "USB:Protect", 11) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            USB_Protect(1);
          }
          else
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
          if (strnicmp(Inrec, "Vck:", 4) == 0)
          {
            /****************************************************************/
            /* See if it is on an NTFS Volume                               */
            /****************************************************************/
            memset(volType, 0, 10);
            isNTFS = 0;

            if (Inrec[5] == ':')
            {
              memset(rootDrive, 0, 5);
              strncpy(rootDrive, Inrec+4, 2);
              rootDrive[2] = '\\';

              if (GetVolumeInformation(rootDrive, volumeName, ARRAYSIZE(volumeName), &serialNumber,
                  &maxComponentLen, &fileSystemFlags, fileSystemName, ARRAYSIZE(fileSystemName)))
              {

                if(consOrFile == 1)
                {
                  consPrefix("[+] ", consGre);
                  printf("Detected File System (%s): %s\n", rootDrive, fileSystemName);
                  fprintf(LogHndl, "[+] Detected File System (%s): %s\n", rootDrive, fileSystemName);
                }

                //What kind of File System is on this Volume?
                if (strnicmp(fileSystemName, "NTFS", 4) == 0)
                {
                  strncpy(volType, "NTFS", 4);
                  isNTFS = 1;
                }
                else
                if (strnicmp(fileSystemName, "FAT32", 5) == 0)
                 strncpy(volType, "FAT32", 5);
                else
                if (strnicmp(fileSystemName, "CDFS", 4) == 0)
                 strncpy(volType, "CDFS", 4);
                else
                 strncpy(volType, "OTHER", 5);
              }
              else
              {
                // Error Trying to get Volume Info
                if(consOrFile == 1)
                {
                  consPrefix("[!] ", consRed);
                  printf("Volume Not Detected on %s\n", rootDrive);
                  fprintf(LogHndl, "[+] Volume Not Detected on %s\n", rootDrive);
                }
 
                strncpy(volType, "NONE", 4);

              }
            }
          }
          else
          if ((strnicmp(Inrec, "CPY:", 4) == 0) || (strnicmp(Inrec, "CPS:", 4) == 0))
          {
            /****************************************************************/
            /* Binary Copy From => To                                       */
            /****************************************************************/
            if (strnicmp(Inrec, "CPS:", 4) == 0)
             iCPS = 1;
            else
             iCPS = 0;

            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            Squish(Inrec);

            memset(Cpyrec, 0, 4096);
            strncpy(Cpyrec, Inrec + 4, 4092);
            twoSplit(Cpyrec);

            if (iPrm2 == 0)
            {
              fprintf(LogHndl, "[!] Copying Requires both a FROM and a TO File\n");

              consPrefix("[!] ", consRed);
              printf("Copying Requires both a FROM and a TO File\n");
            }
            else
            {
              fprintf(LogHndl, "\nCPY: %s\n     %s\n", Cpyrec + iPrm1, Cpyrec + iPrm2);
              consPrefix("\nCPY: ", consBlu);
              printf("%s\n     %s\n", Cpyrec + iPrm1, Cpyrec + iPrm2);

              binCopy(Cpyrec + iPrm1, Cpyrec + iPrm2, 1);
            }
          }
          else
          if ((strnicmp(Inrec, "NCP:", 4) == 0) || (strnicmp(Inrec, "NCS:", 4) == 0))
          {
            /****************************************************************/
            /* First Test Grabbing Max Mem - Error out if you cant          */
            /****************************************************************/
            do
            {
              bufT  = (UCHAR *) malloc(maxMemBytes)  ;

              if(bufT == NULL)
               maxMemBytes -= 26214400; // Subtract 25M

              if (maxMemBytes < 52428800)
              {
                MemAllocErr("Test Data Buffer") ; // Less than 50M - Error Out
              }

            } while (bufT == NULL);


            // Allocation Worked - Delete the buffer and continue...
            free (bufT);

            /****************************************************************/
            /* Binary Copy From => To                                       */
            /****************************************************************/
            if (strnicmp(Inrec, "NCS:", 4) == 0)
             iNCS = 1;
            else
             iNCS = 0;

            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            Squish(Inrec);

            memset(Cpyrec, 0, 4096);
            strncpy(Cpyrec, Inrec + 4, 4092);
            twoSplit(Cpyrec);

            if (iPrm2 == 0)
            {
              fprintf(LogHndl, "[!] Raw Copying Requires both a FROM (File) and a TO (Directory)\n");

              consPrefix("[!] ", consRed);
              printf("Raw Copying Requires both a FROM (File)and a TO (Directory)\n");
            }
            else
            {
              fprintf(LogHndl, "\n%.4s %s\n     %s\n", Inrec, Cpyrec + iPrm1, Cpyrec + iPrm2);

              memset(consTemp, 0, 10);
              sprintf(consTemp, "\n%.4s ", Inrec);
              consPrefix(consTemp, consBlu);
              printf("%s\n     %s\n", Cpyrec + iPrm1, Cpyrec + iPrm2);

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

            fprintf(LogHndl, "\nARN: Parsing Offline Registry AutoRun Keys:\n     %s\n", Inrec + 4);
            consPrefix("\nARN: ", consBlu);
            printf("Parsing Offline Registry AutoRun Keys:\n     %s\n", Inrec + 4);


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
            ORRetcd = OROpenHive(lpORFName, &ORhKey) ;
            if (ORRetcd != ERROR_SUCCESS)
            {
              fprintf(LogHndl, "ARN: COULD NOT Open Offline Registry: %ls (RC: %d)\n", lpORFName, ORRetcd);
              consPrefix("ARN: ", consRed);
              printf("COULD NOT Open Offline Registry: %ls (RC: %d)\n", lpORFName, ORRetcd);
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

                      fprintf(LogHndl, "\nARN: %ls\n     %s\n", ORlpValueName, o32VarRec);
                      consPrefix("\nARN: ", consBlu);
                      printf("%ls\n     %s\n", ORlpValueName, o32VarRec);

                      binCopy(o32VarRec, Cpyrec, 1);
                    }
                    else
                    {
                      fprintf(LogHndl, "\nARN: Not Found - %ls\n     %s\n", ORlpValueName, o32VarRec);
                      consPrefix("\nARN: ", consRed);
                      printf("Not Found - %ls\n     %s\n", ORlpValueName, o32VarRec);
                    }


                    /****************************************************************/
                    /* Always check for 64bit versions - Since this is DeadBox      */
                    /****************************************************************/
                    if (access(o64VarRec, 0) == 0)
                    {
                      sprintf(Cpyrec, "%s\\%s\\%ls(64)-%s\0", BACQDir, ACQDir, ORlpValueName, iPtr3);

                      fprintf(LogHndl, "\nARN: (64bit)%ls\n     %s\n", ORlpValueName, o64VarRec);
                      consPrefix("\nARN: ", consBlu);
                      printf("(64bit)%Ls\n     %s\n", ORlpValueName, o64VarRec);

                      binCopy(o64VarRec, Cpyrec, 1);
                    }
                    else
                    {
                      fprintf(LogHndl, "\nARN: Not Found (64bit) - %ls\n     %s\n", ORlpValueName, o64VarRec);
                      consPrefix("\nARN: ", consRed);
                      printf("Not Found (64bit) - %ls\n     %s\n", ORlpValueName, o64VarRec);
                    }
                  }
                  else
                  if (OpenRC == ERROR_NO_MORE_ITEMS)
                    break;
                  else
                  {
                    consPrefix("[!] ", consRed);
                    printf("Error: %d\n", OpenRC);
                  }
                }

                ORCloseKey(ORphkResult);
              }
              else if (OpenK == ERROR_FILE_NOT_FOUND)
              {
                consPrefix("\nARN: ", consRed);
                printf("Run Key Doesnt exist\n");
              }
              else if (OpenK == ERROR_ACCESS_DENIED)
              {
                consPrefix("\nARN: ", consRed);
                printf("Run Key Access Denied\n");
              }
              else
              {
                consPrefix("\nARN: ", consRed);
                printf("Registry Error: %d\n", OpenK);
              }
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
            
            fprintf(LogHndl, "\nARN: Parsing Live Registry AutoRun Keys\n");
            consPrefix("\nARN: ", consBlu);
            printf("Parsing Live Registry AutoRun Keys\n");


            /****************************************************************/
            /* If 32B - Run Registry Scan Twice - First Time Native,        */
            /*          2nd Time Disable Wow6432Node to get the Keys        */
            /****************************************************************/
            for (samLoop = 0; samLoop < 4; samLoop++)
            {
              /****************************************************************/
              /* Dump AutoRun Keys - HKLM and HKCU                            */
              /****************************************************************/
              if (samLoop == 0)
                OpenK = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, &phkResult);
              else
              if (samLoop == 1)
              {
                /****************************************************************/
                /* If we are 64bit dump 32 bit Keys and visa-versa              */
                /****************************************************************/
                if (strnicmp(Procesr, "AMD64", 5) == 0)
                  OpenK = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samWOW32, &phkResult);
                else
                  OpenK = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samWOW64, &phkResult);
              }
              else
              if (samLoop == 2)
                OpenK = RegOpenKeyEx(hKCU, lpSubKey, ulOptions, samDesired, &phkResult);
              else
              if (samLoop == 3)
              {
                /****************************************************************/
                /* If we are 64bit dump 32 bit Keys and visa-versa              */
                /****************************************************************/
                if (strnicmp(Procesr, "AMD64", 5) == 0)
                  OpenK = RegOpenKeyEx(hKCU, lpSubKey, ulOptions, samWOW32, &phkResult);
                else
                  OpenK = RegOpenKeyEx(hKCU, lpSubKey, ulOptions, samWOW64, &phkResult);
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
                      fprintf(LogHndl, "\nARN: %s\n     %s\n", lpValueName, (LPTSTR)lpData);
                      consPrefix("\nARN: ", consBlu);
                      printf("%s\n     %s\n", lpValueName, (LPTSTR)lpData);

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
                      fprintf(LogHndl, "\nARN: Not Found - %s\n     %s\n", lpValueName, (LPTSTR)lpData);
                      consPrefix("\nARN: ", consRed);
                      printf("Not Found - %s\n     %s\n", lpValueName, (LPTSTR)lpData);
                    }


                    /****************************************************************/
                    /* Check for 64bit versions (if set)                            */
                    /****************************************************************/
                    if (i64x32 == 1)
                    {
                      if (access(o64VarRec, 0) == 0)
                      {
                        fprintf(LogHndl, "\nARN: (64bit)%s\n     %s\n", lpValueName, (LPTSTR)lpData);
                        consPrefix("\nARN: ", consBlu);
                        printf("(64bit)%s\n     %s\n", lpValueName, (LPTSTR)lpData);

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
                        fprintf(LogHndl, "\nARN: Not Found (64bit) - %s\n     %s\n", lpValueName, (LPTSTR) lpData);
                        consPrefix("\nARN: ", consBlu);
                        printf("Not Found (64bit) - %s\n     %s\n", lpValueName, (LPTSTR) lpData);
                      }
                    }
                  }
                  else
                  if (OpenRC == ERROR_NO_MORE_ITEMS)
                    break;
                  else
                  {
                    consPrefix("[!] ", consRed);
                    printf("Error: %d\n", OpenRC);
                  }
                }

                RegCloseKey(phkResult);
              }
              else if (OpenK == ERROR_FILE_NOT_FOUND)
              {
                consPrefix("[!] ", consRed);
                printf("Run Key Doesnt exist\n");
              }
              else if (OpenK == ERROR_ACCESS_DENIED)
              {
                 consPrefix("[!] ", consRed);
                 printf("Run Key Access Denied\n");
              }
              else
              {
                 consPrefix("[!] ", consRed);
                 printf("Registry Error: %d\n", OpenK);
              }
            }
          }
          else
          if (strnicmp(Inrec, "Sig:", 4) == 0)
          {
            /****************************************************************/
            /* Clear the File Signature Table, or Load a signature          */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            if (strnicmp(Inrec + 4, "Clear", 5) == 0)
            {
              iSigCount = 0;

              memset(SigTabl, 0, iSigTMax * iSigSize);
              memset(TypTabl, 0, iSigTMax * iTypSize);

              for(i=0; i<iSigTMax; i++)
                SizTabl[iSigCount] = 0;
            }
            else
            if (strchr(Inrec, '=') != NULL)
            {
              //Parse File Type and signature
              equDelim = strchr(Inrec, '=');
              strncpy(TypTabl+(iSigCount*iTypSize), Inrec+4, equDelim-Inrec-4);

              equDelim++;
              strncpy(SigTabl+(iSigCount*iSigSize), equDelim, iSigSize-1);

              SizTabl[iSigCount] = (int) strlen(equDelim);

              // Sanity Check - Only Bump Counter if we got something!
              if (SizTabl[iSigCount] > 0)
               iSigCount++ ; 
            }
          }
          else
          if (strnicmp(Inrec, "EQU:", 4) == 0)
          {
            /****************************************************************/
            /* Check Lasy Volume Type                                       */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            memset(Cmprec, 0, 4096);
            strncpy(Cmprec, Inrec + 4, 4092);
            twoSplit(Cmprec);

            if (iPrm2 == 0)
            {
              fprintf(LogHndl, "[!] Comparing Requires TWO strings\n");

              consPrefix("[!] ", consRed);
              printf("Comparing Requires TWO Strings\n");
            }
            else
            {
              if(consOrFile == 1)
              {
                consPrefix("[*] ", consYel);

                if(strnicmp(Cmprec + iPrm1, Cmprec + iPrm2, 255) != 0)
                {
                  fprintf(LogHndl, "[*] Strings Are NOT Equal: %s != %s\n", Cmprec + iPrm1, Cmprec + iPrm2);
                  printf("Strings Are NOT Equal: %s != %s\n", Cmprec + iPrm1, Cmprec + iPrm2);
                }
                else
                {
                  fprintf(LogHndl, "[*] Strings ARE Equal: %s\n", Cmprec + iPrm1);
                  printf("Strings ARE Equal: %s\n", Cmprec + iPrm1);
                }
              }
              else
              if(strnicmp(Cmprec + iPrm1, Cmprec + iPrm2, 255) != 0)
               RunMe++;
            }
          }
          else
          if (strnicmp(Inrec, "NEQ:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            memset(Cmprec, 0, 4096);
            strncpy(Cmprec, Inrec + 4, 4092);
            twoSplit(Cmprec);

            if (iPrm2 == 0)
            {
              fprintf(LogHndl, "[!] Comparing Requires TWO strings\n");

              consPrefix("[!] ", consRed);
              printf("Comparing Requires TWO Strings\n");
            }
            else
            {
              if(consOrFile == 1)
              {
                consPrefix("[*] ", consYel);
                if(strnicmp(Cmprec + iPrm1, Cmprec + iPrm2, 255) == 0)
                {
                  fprintf(LogHndl, "[*] Strings are (not not) Equal: %s\n", Cmprec + iPrm1);
                  printf("Strings are (not not) Equal: %s\n", Cmprec + iPrm1);
                }
                else
                {
                  fprintf(LogHndl, "[*] Strings are NOT Equal: %s != %s\n", Cmprec + iPrm1, Cmprec + iPrm2);
                  printf("Strings are NOT Equal: %s != %s\n", Cmprec + iPrm1, Cmprec + iPrm2);
                }
              }         
              else
              if(strnicmp(Cmprec + iPrm1, Cmprec + iPrm2, 255) == 0)
               RunMe++;
            }
          }
          else
          if (strnicmp(Inrec, "VER:", 4) == 0)
          {
            /****************************************************************/
            /* Check Running OS Version or Type (Server, Client)            */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);

              if (strnicmp(Inrec+4, "Server", 6) == 0)
              {
                if(iIsServer == 1)
                {  
                  fprintf(LogHndl, "[*] Windows OS Type is: Server\n");
                  printf("Windows OS Type is: Server\n");
                }
                else
                {
                  fprintf(LogHndl, "[*] Windows OS Type is: Client - Not: Server\n");
                  printf("Windows OS Type is: Client - Not: Server\n");
                }
              }
              else
              if (strnicmp(Inrec+4, "Client", 6) == 0)
              {
                if(iIsServer == 0)
                {  
                  fprintf(LogHndl, "[*] Windows OS Type is: Client\n");
                  printf("Windows OS Type is: Client\n");
                }
                else
                {
                  fprintf(LogHndl, "[*] Windows OS Type is: Server - Not: Client\n");
                  printf("Windows OS Type is: Server - Not: Client\n");
                }
              }
              else
              if (strnicmp(shortWinVer, Inrec+4, 10) != 0)
              {
                fprintf(LogHndl, "[*] Windows OS is: %s - Not: %s\n", shortWinVer, Inrec+4);
                printf("Windows OS is: %s - Not: %s\n", shortWinVer, Inrec+4);
              }
              else
              {
                fprintf(LogHndl, "[*] Windows OS is: %s\n", shortWinVer);
                printf("Windows OS is: %s\n", shortWinVer);
              }
            }         
            else
            {
              if (strnicmp(Inrec+4, "Server", 6) == 0)
              {
                if(iIsServer != 1)
                 RunMe++;
              }
              else
              if (strnicmp(Inrec+4, "Client", 6) == 0)
              {
                if(iIsServer != 0)
                 RunMe++;
              }
              else
              if (strnicmp(shortWinVer, Inrec+4, 10) != 0)
                RunMe++;
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

            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);
              if (LastRC != ChkRC)
              {
                fprintf(LogHndl, "[*] Last Return Code was not: %d - It was: %d\n", ChkRC, LastRC);
                printf("Last Return Code was not: %d - It was: %d\n", ChkRC, LastRC);
              }
              else
              {
                fprintf(LogHndl, "[*] Last Return was: %d\n", LastRC);
                printf("Last Return Code was: %d\n", LastRC);
              }
            }         
            else
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

            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);
              if (LastRC == ChkRC)
              {
                fprintf(LogHndl, "[*] Last Return was (not not): %d\n", LastRC);
                printf("Last Return Code was (not not): %d\n", LastRC);
              }
              else
              {
                fprintf(LogHndl, "[*] Last Return Code was not: %d - It was: %d\n", ChkRC, LastRC);
                printf("Last Return Code was not: %d - It was: %d\n", ChkRC, LastRC);
              }
            }         
            else
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

            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);
              if (LastRC >= ChkRC)
              {
                fprintf(LogHndl, "[*] Last Return Code was not Less Than: %d - It was: %d\n", ChkRC, LastRC);
                printf("Last Return Code was not Less Than: %d - It was: %d\n", ChkRC, LastRC);
              }
              else
              {
                fprintf(LogHndl, "[*] Last Return was Less Than: %d - It was: %d\n", ChkRC, LastRC);
                printf("Last Return Code was Less Than: %d - It was: %d\n", ChkRC, LastRC);
              }
            }         
            else
            if (LastRC >= ChkRC)
              RunMe++;
          }
          else
          if (strnicmp(Inrec, "RC>:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code > n                                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            ChkRC = atoi(Inrec + 4);

            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);
              if (LastRC <= ChkRC)
              {
                fprintf(LogHndl, "[*] Last Return Code was not Greate Than: %d - It was: %d\n", ChkRC, LastRC);
                printf("Last Return Code was not Greater Than: %d - It was: %d\n", ChkRC, LastRC);
              }
              else
              {
                fprintf(LogHndl, "[*] Last Return was Greater Than: %d - It was: %d\n", ChkRC, LastRC);
                printf("Last Return Code was Greater Than: %d - It was: %d\n", ChkRC, LastRC);
              }
            }         
            else
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

            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);
              if (access(ChkFile, 0) != 0)
              {
                fprintf(LogHndl, "[*] File Does Not Exist: %s\n", ChkFile);
                printf("File Does Not Exist: %s\n", ChkFile);
              }
              else
              {
                fprintf(LogHndl, "File Exists: %s\n", ChkFile);
                printf("File Exists: %s\n", ChkFile);
              }
            }         
            else
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

            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);
              if (strnicmp(Procesr, "AMD64", 5) != 0)
              {
                fprintf(LogHndl, "[*] Not running in 64Bit. Processor: %s\n", Procesr);
                printf("Not running in 64Bit. Processor: %s\n", Procesr);
              }
              else
              {
                fprintf(LogHndl, "Running in 64Bit. Processor: %s\n", Procesr);
                printf("Running in 64Bit. Processor: %s\n", Procesr);
              }
            }         
            else
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
            
            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);
              if (strnicmp(Procesr, "X86", 3) != 0)
              {
                fprintf(LogHndl, "[*] Not running in 32Bit. Processor: %s\n", Procesr);
                printf("Not running in 32Bit. Processor: %s\n", Procesr);
              }
              else
              {
                fprintf(LogHndl, "Running in 32Bit. Processor: %s\n", Procesr);
                printf("Running in 32Bit. Processor: %s\n", Procesr);
              }
            }         
            else
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

            if(consOrFile == 1)
            {
              consPrefix("[*] ", consYel);
              if (access(ChkFile, 0) == 0)
              {
                fprintf(LogHndl, "[*] File Does (not not) Exist: %s\n", ChkFile);
                printf("File Does (not not) Exist: %s\n", ChkFile);
              }
              else
              {
                fprintf(LogHndl, "File Does Not Exist: %s\n", ChkFile);
                printf("File Does Not Exist: %s\n", ChkFile);
              }
            }         
            else
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
              fprintf(LogHndl, "[!] Required File Not Found: %s - Exiting!\n", Inrec + 4);
              consPrefix("[!] ", consRed);
              printf("Required File Not Found: %s - Exiting!\n", Inrec + 4);
              cleanUp_Exit(3);
              exit (3);
            }
            else
            {
              fprintf(LogHndl, "[+] Required File Found: %s\n", Inrec + 4);
              consPrefix("[+] ", consGre);
              printf("Required File Found: %s\n", Inrec + 4);
            }
          }
          else
          if (strnicmp(Inrec, "SAY:", 4) == 0)
          {
            // Echo To Screen and Log
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
            getKey = getchar();

            if ((getKey == 81) || (getKey == 113))
            {
              fprintf(LogHndl, "\n[!] You have requested Achoir to Quit.\n");
              consPrefix("\n[!] ", consRed);
              printf("You have requested Achoir to Quit.\n");
              cleanUp_Exit(0);
              exit(0);
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

            fprintf(LogHndl, "[+] Now Hashing Acquisition Files\n");

            consPrefix("[+] ", consGre);
            printf("Now Hashing Acquisition Files\n");
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
            
            fprintf(LogHndl, "[+] Now Hashing AChoir Files\n");
            consPrefix("[+] ", consGre);
            printf("Now Hashing AChoir Files\n");
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
          if (strnicmp(Inrec, "DSK:", 4) == 0)
          {
            /****************************************************************/
            /* Get the Attached Disk Drives for the &DSK variable (Loop)    */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            if(strnicmp(Inrec+4, "Remov", 5) == 0)
             dskTyp = 2;
            else
            if(strnicmp(Inrec+4, "Fixed", 5) == 0)
             dskTyp = 3;
            else
            if(strnicmp(Inrec+4, "Remot", 5) == 0)
             dskTyp = 4;
            else
            if(strnicmp(Inrec+4, "Cdrom", 5) == 0)
             dskTyp = 5;
            else
            if(strnicmp(Inrec+4, "Ramdi", 5) == 0)
             dskTyp = 6;
            else
             dskTyp = 3;


            //If Disk Type Matches, Write it Out
            DskHndl = fopen(ForDisk, "w");
            if(DskHndl != NULL)
            {
              for (dskNum = 0; dskNum < 26; dskNum++)
              {
                memset(dskNam, 0, 10);
                sprintf(dskNam, "%c:\\", Alphabet[dskNum]);

                if(GetDriveType(dskNam) == dskTyp)
                 fprintf(DskHndl,"%c\n", Alphabet[dskNum]);
              }
              fclose(DskHndl);
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

            sprintf(MD5File, "%s\\%s\\Cache\\ForFiles\0", BaseDir, ACQName);
            MD5Hndl = fopen(MD5File, "w");

            if (MD5Hndl != NULL)
            {
              ListDir(Inrec + 4, "FOR");

              if (iNative == 0)
              {
                if(strnicmp(Inrec+4+strlen(WinRoot), "\\System32\\", 10) == 0)
                {
                  memset(TempDir, 0, 1024);
                  sprintf(TempDir, "%s\\Sysnative\\%s\0", WinRoot, Inrec+4+strlen(WinRoot)+10);

                  if(iLogOpen == 1)
                   fprintf(LogHndl, "[*] Non-Native Flag Has Been Detected - Adding Sysnative Redirection: \n %s\n", TempDir);

                  consPrefix("[*] ", consYel);
                  printf("Non-Native Flag Has Been Detected - Adding Sysnative Redirection: \n %s\n", TempDir);

                  ListDir(TempDir, "FOR");
                }
              }

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

            consPrefix("BYE: ", consBlu);
            printf("Exiting with RC = %d\n", LastRC);

            if (access(ForFile, 0) == 0)
              unlink(ForFile);

            if (access(ForDisk, 0) == 0)
              unlink(ForDisk);
            
            //fclose(LogHndl);
            cleanUp_Exit(LastRC);
            exit (LastRC);
          }
          else
          if (strnicmp(Inrec, "USR:", 4) == 0)
          {
            /****************************************************************/
            /* Map to an External Drive & Set it to ACQ Directory           */
            /****************************************************************/
            if (Inrec[4] =='?')
            {
              consPrefix("[?] ", consYel);
              consInput("Enter Share Mapping UserId> ", 1, 0);
              memset(inUser, 0, 255);
              strncpy(inUser, Conrec, 254);
            }
            else
            {
              strtok(Inrec, "\n");
              strtok(Inrec, "\r");

              memset(inUser, 0, 255);
              strncpy(inUser, Inrec + 4, 254);
            }
          }
          else
          if (strnicmp(Inrec, "PWD:", 4) == 0)
          {
            /****************************************************************/
            /* Map to an External Drive & Set it to ACQ Directory           */
            /****************************************************************/
            if (Inrec[4] =='?')
            {
              consPrefix("[?] ", consYel);
              consInput("Share Mapping Password> ", 1, 1);
              memset(inPass, 0, 255);
              strncpy(inPass, Conrec, 254);
            }
            else
            {
              strtok(Inrec, "\n");
              strtok(Inrec, "\r");

              memset(inPass, 0, 255);
              strncpy(inPass, Inrec + 4, 254);
            }
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

            fprintf(LogHndl, "[+] Max Memory/File Bytes Set: %lu\n", maxMemBytes);
            consPrefix("[+] ", consGre);
            printf("Max Memory/File Bytes Set: %lu\n", maxMemBytes);
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
          if (strnicmp(Inrec, "SHR:", 4) == 0)
          {
            /****************************************************************/
            /* Create a Local Share SHR:<Path> <Shr Name>                   */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            memset(Shrrec, 0, 1024);
            strncpy(Shrrec, Inrec + 4, 1024);
            twoSplit(Shrrec);

            if (iPrm2 == 0)
             netLocalShare(cName, Inrec + 4, "Ach-Rmt", 1);
            else
             netLocalShare(cName, Shrrec + iPrm1, Shrrec + iPrm2, 1);
          }
          else
          if (strnicmp(Inrec, "SHD:", 4) == 0)
          {
            /****************************************************************/
            /* Delete a Local Share SHD:<Shr Name>                          */
            /****************************************************************/
            strtok(Inrec, "\n");
            strtok(Inrec, "\r");

            netShareDel(Inrec + 4, 1);
          }
          else
          if (strnicmp(Inrec, "SET:NCP=NODCMP", 14) == 0)
          {
            /****************************************************************/
            /* Set Raw NTFS Copy to RAW ONLY                                */
            /****************************************************************/
            setNCP = 0;
          }
          else
          if (strnicmp(Inrec, "SET:NCP=RAWONLY", 15) == 0)
          {
            /****************************************************************/
            /* Set Raw NTFS to LZNT1 Decompress (Legacy)                    */
            /****************************************************************/
            setNCP = 1;
          }
          else
          if (strnicmp(Inrec, "SET:NCP=DECOMP", 14) == 0)
          {
            /****************************************************************/
            /* Set Raw NTFS to LZNT1 Decompress                             */
            /****************************************************************/
            setNCP = 1;
          }
          else
          if (strnicmp(Inrec, "SET:NCP=OSCOPY", 14) == 0)
          {
            /****************************************************************/
            /* Set Raw NTFS Copy to RAW ONLY                                */
            /****************************************************************/
            setNCP = 2;
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

            fprintf(LogHndl, "\nXIT: Exit Program Set:\nXit: %s\n", XitCmd);

            consPrefix("\nXIT: ", consBlu);
            printf("Exit Program Set:\nXit: %s\n", XitCmd);
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

            fprintf(LogHndl, "\nSYS: %s\n", TempDir);
            consPrefix("\nSYS: ", consBlu);
            printf("%s\n", TempDir);
            LastRC = system(TempDir);
            fprintf(LogHndl, "Return Code: %d\n", LastRC);
          }
          else
          if ((strnicmp(Inrec, "EXE:", 4) == 0) || (strnicmp(Inrec, "EXA:", 4) == 0) || (strnicmp(Inrec, "EXB:", 4) == 0))
          {
            if(strnicmp(Inrec, "EXE:", 4) == 0)
             iExec = 1 ;
            else            
            if(strnicmp(Inrec, "EXA:", 4) == 0)
             iExec = 2 ;
            else            
            if(strnicmp(Inrec, "EXB:", 4) == 0)
             iExec = 3 ;
            else
             iExec = 1 ;

            /****************************************************************/
            /* Spawn an Executable                                          */
            /*  EXE - P_Wait    (Default is Blocked/Sequential)             */
            /*  EXA - P_NOWAIT  (Asyncronous/Not Blocked)                   */
            /*  EXB - P_DETACH  (Run as a Background Process)               */
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
              fprintf(LogHndl, "[!] Program Not Found\n");

              consPrefix("[!] ", consRed);
              printf("Program Not Found\n");
            }
            else
            {
              FileMD5(TempDir);

              /****************************************************************/
              /* EXA, EXB, or EXE                                             */
              /****************************************************************/
              if(iExec == 1)
              {
                fprintf(LogHndl, "\nEXE: %s\n", Exerec + iPrm1);
                consPrefix("\nEXE: ", consBlu);
              }
              else
              if(iExec == 2)
              {
                fprintf(LogHndl, "\nEXA: %s\n", Exerec + iPrm1);
                consPrefix("\nEXA: ", consBlu);
              }
              else
              if(iExec == 3)
              {
                fprintf(LogHndl, "\nEXB: %s\n", Exerec + iPrm1);
                consPrefix("\nEXB: ", consBlu);
              }
              printf("%s\n", Exerec + iPrm1);


              // Processing of 1, 2, or 3 sets of Command Line Parameters
              if (iPrm3 > 0)
              {
                // 3 Command Line Parameters
                // Redact iPrm2 if it has a Password
                Redactor(Exerec+iPrm2, Redrec);
                fprintf(LogHndl, "   : %s\n", Redrec);
                printf("   : %s\n", Redrec);

                // Redact iPrm3 if it has a Password
                Redactor(Exerec+iPrm3, Redrec);
                fprintf(LogHndl, "   : %s\n", Redrec);
                printf("   : %s\n", Redrec);

                fprintf(LogHndl, "MD5: %s\n", MD5Out);
                consPrefix("MD5: ", consGre);
                printf("%s\n", MD5Out);

                if(iExec == 1)
                 LastRC = (int) spawnlp(P_WAIT, TempDir, TempDir, Exerec + iPrm2, Exerec + iPrm3, NULL);
                else
                if(iExec == 2)
                 LastRC = (int) spawnlp(P_NOWAIT, TempDir, TempDir, Exerec + iPrm2, Exerec + iPrm3, NULL);
                else
                if(iExec == 3)
                 LastRC = (int) spawnlp(P_DETACH, TempDir, TempDir, Exerec + iPrm2, Exerec + iPrm3, NULL);
              }
              else
              if (iPrm2 > 0)
              {
                // 2 Command Line Parameters
                // Redact iPrm2 if it has a Password
                Redactor(Exerec+iPrm2, Redrec);
                fprintf(LogHndl, "   : %s\n", Redrec);
                printf("   : %s\n", Redrec);

                fprintf(LogHndl, "MD5: %s\n", MD5Out);
                consPrefix("MD5: ", consGre);
                printf("%s\n", MD5Out);

                if(iExec == 1)
                 LastRC = (int) spawnlp(P_WAIT, TempDir, TempDir, Exerec + iPrm2, NULL);
                else
                if(iExec == 2)
                 LastRC = (int) spawnlp(P_NOWAIT, TempDir, TempDir, Exerec + iPrm2, NULL);
                else
                if(iExec == 3)
                 LastRC = (int) spawnlp(P_DETACH, TempDir, TempDir, Exerec + iPrm2, NULL);
              }
              else
              {
                // 1 Command Line Parameter
                // No Redaction necessary
                fprintf(LogHndl, "MD5: %s\n", MD5Out);
                consPrefix("MD5: ", consGre);
                printf("%s\n", MD5Out);

                if(iExec == 1)
                 LastRC = (int) spawnlp(P_WAIT, TempDir, TempDir, NULL);
                else
                if(iExec == 2)
                 LastRC = (int) spawnlp(P_NOWAIT, TempDir, TempDir, NULL);
                else
                if(iExec == 3)
                 LastRC = (int) spawnlp(P_DETACH, TempDir, TempDir, NULL);
              }


              if (LastRC != 0)
              {
                fprintf(LogHndl, "[!] Spawn Error(%d): %s\n", errno, strerror(errno));
                consPrefix("[!] ", consRed);
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
              fprintf(LogHndl, "[!] AChoir Safe Command Shell Not Found!\n");
              fprintf(LogHndl, "    Bypassing %s\n\n", Inrec);

              consPrefix("[!] ", consRed);
              printf("AChoir Safe Command Shell Not Found!\n");
              printf("    Bypassing %s\n\n", Inrec);
            }
            else
            {
              FileMD5(CmdExe);
              if (strnicmp(MD5Out, CmdHash, 32) != 0)
              {
                fprintf(LogHndl, "[!] Command Shell Not Approved for AChoir (Bad Hash)!\n");
                fprintf(LogHndl, "    Bypassing %s\n\n", Inrec);

                consPrefix("[!] ", consRed);
                printf("Command Shell Not Approved for AChoir (Bad Hash)!\n");
                printf("    Bypassing %s\n\n", Inrec);
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
                  fprintf(LogHndl, "\nCMD: %s\n", Exerec + iPrm1);
                  consPrefix("\nCMD: ", consBlu);
                  printf("%s\n", Exerec + iPrm1);

                  // Redact iPrm2 if it has a Password
                  Redactor(Exerec+iPrm2, Redrec);
                  fprintf(LogHndl, "   : %s\n", Redrec);
                  printf("   : %s\n", Redrec);

                  // Redact iPrm3 if it has a Password
                  Redactor(Exerec+iPrm3, Redrec);
                  fprintf(LogHndl, "   : %s\n", Redrec);
                  printf("   : %s\n", Redrec);

                  fprintf(LogHndl, "MD5: Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);
                  consPrefix("MD5: ", consGre);
                  printf("Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);

                  LastRC = (int)spawnlp(P_WAIT, CmdExe, CmdExe, "/c", TempDir, Exerec + iPrm2, Exerec + iPrm3, NULL);
                }
                else
                if (iPrm2 > 0)
                {
                  fprintf(LogHndl, "\nCMD: %s\n", Exerec + iPrm1);
                  consPrefix("\nCMD: ", consBlu);
                  printf("%s\n", Exerec + iPrm1);

                  // Redact iPrm2 if it has a Password
                  Redactor(Exerec+iPrm2, Redrec);
                  fprintf(LogHndl, "   : %s\n ", Redrec);
                  printf("   : %s\n", Redrec);

                  fprintf(LogHndl, "MD5: Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);
                  consPrefix("MD5: ", consGre);
                  printf("Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);

                  LastRC = (int)spawnlp(P_WAIT, CmdExe, CmdExe, "/c", TempDir, Exerec + iPrm2, NULL);
                }
                else
                {
                  fprintf(LogHndl, "\nCMD: %s\n", Exerec + iPrm1);
                  consPrefix("\nCMD: ", consBlu);
                  printf("%s\n", Exerec + iPrm1);

                  fprintf(LogHndl, "MD5: Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);
                  consPrefix("MD5: ", consGre);
                  printf("Cmd/Pgm: %s/%s\n", CmdHash, MD5Out);

                  LastRC = (int)spawnlp(P_WAIT, CmdExe, CmdExe, "/c", TempDir, NULL);
                }


                if (LastRC != 0)
                {
                  fprintf(LogHndl, "[!] Spawn Error(%d): %s\n", errno, strerror(errno));
                  consPrefix("[!] ", consRed);
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

            /****************************************************************/
            /* This code changed to be JUST CurrFil to allow HTTP Get into  */ 
            /* both the &Dir or &Acq (or anywhere else).  This is to allow  */
            /* HTTP Get for both Building the Toolkit and Acquisition       */
            /* That means that CurrFil MUST BE A FULL PATH TO THE NEW FILE  */
            /****************************************************************/
            //sprintf(WGetFile, "%s\\%s%s\0", BaseDir, CurrDir, CurrFil);
            sprintf(WGetFile, "%s\0", CurrFil);
            fprintf(LogHndl, "[+] Getting: %s\n", WGetFile);
            consPrefix("[+] ", consGre);
            printf("Getting: %s\n", WGetFile);

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
                            consPrefix("[!] ", consRed);
                            printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                            fprintf(LogHndl, "[!] Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                          }

                          if (dwSize > 0)
                          {
                            // Allocate space for the buffer.
                            pszOutBuffer = new (std::nothrow) char[dwSize + 1];
                            if (pszOutBuffer == NULL)
                            {
                              consPrefix("[!] ", consRed);
                              printf("Ran Out Of Memory Reading HTTP\n");
                              fprintf(LogHndl, "[!] Ran Out Of Memory Reading HTTP\n");
                              dwSize = 0;
                            }
                            else
                            {
                              // Read the data.
                              ZeroMemory(pszOutBuffer, dwSize + 1);

                              if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
                              {
                                consPrefix("[!] ", consRed);
                                printf("Error %u in WinHttpReadData.\n", GetLastError());
                                fprintf(LogHndl, "[!] Error %u in WinHttpReadData.\n", GetLastError());
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
                        consPrefix("[!] ", consRed);
                        printf("Error %d has occurred.\n", GetLastError());
                        fprintf(LogHndl, "[!] Error %d has occurred.\n", GetLastError());
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

          fflush(stdout); //More PSExec Friendly
          
        }

        if ((ForMe == 1) && (ForHndl != NULL))
          fclose(ForHndl);

        if ((LstMe == 1) && (LstHndl != NULL))
          fclose(LstHndl);

        if ((DskMe == 1) && (DskHndl != NULL))
          fclose(DskHndl);

        fflush(stdout); //More PSExec Friendly

      }

      if(consOrFile == 1)
       consPrefix(">>> ", consGre);

      fflush(stdout); //More PSExec Friendly

    }

    /****************************************************************/
    /* End Of Script Processing Code                                */
    /****************************************************************/
    if(consOrFile == 0)
     fclose(IniHndl);

    fflush(stdout); //More PSExec Friendly

  }
  else
  {
    fprintf(LogHndl, "\n[!] Input Script Not Found:\n     %s\n\n", IniFile);

    consPrefix("\n[!] ", consRed);
    printf("Input Script Not Found:\n     %s\n\n", IniFile);
    cleanUp_Exit(1);
    exit (1);
  }

  fflush(stdout); //More PSExec Friendly


  /****************************************************************/
  /* Cleanup                                                      */
  /****************************************************************/
  if (RunMe > 0)
  {
    fprintf(LogHndl, "[!] You have and extra END: Hanging! Check your Logic.\n");

    consPrefix("[!] ", consRed);
    printf("You have and extra END: Hanging! Check your Logic.\n");
  }

  fflush(stdout); //More PSExec Friendly
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
  fprintf(LogHndl, "[!] Error Allocating Enough Memory For: %s\n\n", ErrType);

  consPrefix("[!] ", consRed);
  printf("Error Allocating Enough Memory For: %s\n\n", ErrType);

  fflush(stdout); //More PSExec Friendly

  exit(3);
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
/* Redact a String to delete sensitive data                     */
/****************************************************************/
size_t Redactor(char *inRedact, char *outRedact)
{
  size_t inRdi, outRdi, RdiFlag, RdLen;

  RdiFlag = outRdi = 0;
  RdLen = strlen(inRedact);
  memset (outRedact, 0, 1024);

  //Redacted String... Max Size = 1000
  if(RdLen > 1000)
   RdLen = 1000;

  for (inRdi = 0; inRdi < RdLen; inRdi++)
  {
    if (RdiFlag == 1)
    {
      //Strings delimied by space or dbl-quote
      if(inRedact[inRdi] == ' ')
      {
       RdiFlag = 0;
       outRedact[outRdi] = inRedact[inRdi];
       outRdi++;
      }
      
      if(inRedact[inRdi] == '"')
      {
       RdiFlag = 0;
       outRedact[outRdi] = inRedact[inRdi];
       outRdi++;
      }
    }
    else
    if (strnicmp(inRedact+inRdi, "pwd:", 4) == 0)
    {
      // Redact out passwords - we dont want passwords in log files
      strncpy(outRedact+outRdi, "PWD:*Redacted*\0", 15);
      outRdi+=14;
      RdiFlag = 1;
    }
    else
    if (RdiFlag == 0)
    {
      outRedact[outRdi] = inRedact[inRdi];
      outRdi++;
    }
  }

  RdLen = strlen(outRedact);
  return RdLen;
}



/****************************************************************/
/* Remove Indented Spaces and Tabs                              */
/****************************************************************/
size_t unIndent(char *SqString)
{
  size_t Sqi, Sqx, SqLen;

  //Zap any preceding spaces or tabs..
  for (Sqi = 0; Sqi < strlen(SqString); Sqi++)
  {
    if ((SqString[Sqi] != ' ') && (SqString[Sqi] != 9))
      break;
  }

  if (Sqi > 0)
  {
    for (Sqx = 0; Sqx < strlen(SqString)+Sqi; Sqx++)
     SqString[Sqx] = SqString[Sqx+Sqi];

    // Null Terminate the string
    SqString[Sqx+1] = '\0';
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
        fprintf(LogHndl, "[!] Max Path Exceeded: %s%s\n", RootDir, inName);
 
        consPrefix("[!] ", consRed);
        printf("Max Path Exceeded: %s%s\n", RootDir, inName);

        fflush(stdout); //More PSExec Friendly
        return 0;
      }

      //if (stristr(RootDir, "Application Data\\Application Data\\Application Data\0") > 0)
      if (stristr(RootDir, "\\Application Data\\Application Data\\\0") > 0)
      {
        fprintf(LogHndl, "[!] Directory Recursion Error: %s%s\n", RootDir, inName);

        consPrefix("[!] ", consRed);
        printf("Directory Recursion Error: %s%s\n", RootDir, inName);

        fflush(stdout); //More PSExec Friendly
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
    fprintf(HtmHndl, "<Center><table width=98%%>\n");
    fprintf(HtmHndl, "<tr><td align=left>\n");
    fprintf(HtmHndl, "<button onclick=\"window.history.back()\">&lt;&lt;</button>\n");
    fprintf(HtmHndl, "</td><td align=center>\n");
    fprintf(HtmHndl, "<a href=file:./ target=AFrame> Root </a>\n");
  }
  else
  {
    fprintf(HtmHndl, "[!] Could not Create Artifact Index: %s\n", HtmFile);

    consPrefix("[!] ", consRed);
    printf("Could not Create Artifact Index: %s\n", HtmFile);
  }

  fflush(stdout); //More PSExec Friendly
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

  char tmpFrmFile[4096];
  char tmpTooFile[4096];
  int iFileCount = 0;
  int iFileFound = 0;
  int TimeNotGood = 0;
  int setOwner = 0;

  FILE* FrmHndl;
  FILE* TooHndl;
  HANDLE HndlToo;

  DWORD dwRtnCode = 0;
  DWORD SecLen, LenSec;
  PSID pSidOwner = NULL;
  BOOL pFlag = FALSE;
  
  // Signature Checking Variables
  int i;
  CHAR filetype[11] = "\0";
  char *dotPos;


  /****************************************************************/
  /* Make Sure the File is Not There - Don't Overwrite!           */
  /****************************************************************/
  memset(tmpTooFile, 0, 4096);
  snprintf(tmpTooFile, 4090, "%s", TooFile);

  memset(tmpFrmFile, 0, 4096);
  snprintf(tmpFrmFile, 4090, "%s", FrmFile);


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
    fprintf(LogHndl, "[*] Destination File Already Exists. \n     Renamed To: %s\n", tmpTooFile);
    consPrefix("[*] ", consYel);
    printf("Destination File Already Exists. \n     Renamed To: %s\n", tmpTooFile);
  }


  iFileFound = 1;  // Assume Yes, Found
  if (access(tmpFrmFile, 0) != 0)
  {
    iFileFound = 0; // Not Found

    if(binLog == 1)
      fprintf(LogHndl, "[!] Source Copy File Not Found: \n %s\n", tmpFrmFile);

    consPrefix("[!] ", consRed);
    printf("Source Copy File Not Found: \n %s\n", tmpFrmFile);


    // Check for Sysnative edge case (running 32 bit on 64 bit)
    //if (strnicmp(Procesr, "X86", 3) == 0)
    if (iNative == 0)
    {
      iFileFound = 1; //Wait... Maybe it's a file Redirect

      if(strnicmp(FrmFile+strlen(WinRoot), "\\System32\\", 10) == 0)
      {
        memset(tmpFrmFile, 0, 4096);
        sprintf(tmpFrmFile, "%s\\Sysnative\\%s\0", WinRoot, FrmFile+strlen(WinRoot)+10);

        if(binLog == 1)
          fprintf(LogHndl, "[*] Non-Native Flag Has Been Detected - Trying Sysnative Redirection: \n %s\n", tmpFrmFile);

        consPrefix("[*] ", consYel);
        printf("Non-Native Flag Has Been Detected - Trying Sysnative Redirection: \n %s\n", tmpFrmFile);

        if (access(tmpFrmFile, 0) != 0)
        {
          iFileFound = 0; //No... Sorry... Not Sysnative

          if(binLog == 1)
            fprintf(LogHndl, "[*] Sysnative Source Copy Also File Not Found: \n %s\n", tmpFrmFile);

          consPrefix("[*] ", consYel);
          printf("Sysnative Source Copy Also File Not Found: \n %s\n", tmpFrmFile);
          fflush(stdout); //More PSExec Friendly
          return 0;
        }
        else
        {
          iFileFound = 1; // Yes... Substitution Successful

          if(binLog == 1)
            fprintf(LogHndl, "[*] Sysnative Source Copy File Found, Now Substituting.\n");

          consPrefix("[*] ", consYel);
          printf("Sysnative Source Copy File Found, Now Substituting.\n");
          fflush(stdout); //More PSExec Friendly
        }
      }
      else
      {
        fflush(stdout); //More PSExec Friendly
        return 0;
      }

    }

  }


  if(iFileFound == 1)
  {
    /****************************************************************/
    /* Get the original TimeStamps                                  */
    /****************************************************************/
    _stat(tmpFrmFile, &Frmstat);


    /****************************************************************/
    /* Get the SID (File Owner) of the file - Security Descripter   */
    /****************************************************************/
    gotOwner = 0;

    /****************************************************************/
    /* NOTE: Use Static Security Descriptor Buffer. Its Safer       */
    /****************************************************************/
    SecLen = 200;

    // Populate the Security Description Structure
    if (GetFileSecurity(tmpFrmFile, OWNER_SECURITY_INFORMATION, SecDesc, SecLen, &LenSec))
    {
      if (GetSecurityDescriptorOwner(SecDesc, &pSidOwner, &pFlag))
      {
        gotOwner = 1;

        convert_sid_to_string_sid(pSidOwner, SidString);
      }
    }


    /****************************************************************/
    /* Open Input File - Make sure we can read it!                  */
    /****************************************************************/
    FrmHndl = fopen(tmpFrmFile, "rb"); // Open From File
    if (FrmHndl == NULL)
    {
      consPrefix("[!] ", consRed);
      printf("Could Not Open File for Reading - File Copy Bypassed.\n");
      fprintf(LogHndl, "[!] Could Not Open File for Reading - File copy Bypassed.\n");

      fflush(stdout); //More PSExec Friendly
      return 1;
    }


    /****************************************************************/
    /* Copy File Code                                               */
    /****************************************************************/
    iCPSFound = 0;                  // Default to NOT Found

    // For CPY: it's ALWAYS found, for CPS: do the compare
    if(iCPS == 0)
     iCPSFound = 1;
    else
    if(iCPS == 1)
    {
      /****************************************************************/
      /* If we are doing an CPS - Read the first 32 Bytes and compare */
      /*  to the Signature Table entries                              */
      /****************************************************************/
      // Start with a clean slate
      memset(Cpybuf, 0, iSigSize);
      memset(tmpSig, 0, iSigSize);

      // Read in signature bytes
      inSize = fread(Cpybuf, 1, iSigSize, FrmHndl);

      // Convert n Bytes into n*2 Hex Chars
      for (i=0; i < (iSigSize-1)/2; i++)
      {
        sprintf(tmpSig+(i*2), "%02x", Cpybuf[i]);
      }

      // Parse Out the FileType for Signature Checking
      memset(filetype, 0, 11);
      dotPos = strrchr(tmpFrmFile, '.') ;

      if(dotPos !=NULL)
       strncpy(filetype, dotPos + 1, 10);


      // Compare with the Signature and FileType Tables
      for (i=0; i < iSigCount; i++)
      {
        if((strnicmp(tmpSig, SigTabl+(i*iSigSize), SizTabl[i]) == 0) && (strlen(SigTabl+(i*iSigSize)) > 0))
        {
          iCPSFound = 1;

          consPrefix("     (Sig) ", consGre);
          printf("Header Signature Match Found in File (%s)\n", tmpSig);
          fprintf(LogHndl, "     (Sig)Header Signature Match Found in File (%s)\n", tmpSig);
          break;
        }

        if((strnicmp(filetype, TypTabl+(i*iTypSize), iTypSize) == 0) && (strlen(filetype) > 0))
        {
          iCPSFound = 1;
          consPrefix("     (Sig) ", consGre);
          printf("File Extention Match Found (%s)\n", filetype);
          fprintf(LogHndl, "     (Sig)File Extention Match Found (%s)\n", filetype);
          break;
        }
      }

      if(iCPSFound == 0)
      {
        consPrefix("     (Sig) ", consRed);
        printf("No Signature Match in File - File Copy Bypassed.\n");
        fprintf(LogHndl, "     (Sig)No Signature Match in File - File copy Bypassed.\n");

        fclose(FrmHndl);
        fflush(stdout); //More PSExec Friendly
        return 1;
      }
    }

    // Complete the copy if we are doing an NCP: - or if the NCS: Signature was found
    if (iCPSFound == 1)
    {
      rewind(FrmHndl); // Make sure we start at the top

      //FrmHndl = fopen(tmpFrmFile, "rb");
      TooHndl = fopen(tmpTooFile, "wb");

      if ((FrmHndl != NULL) && (TooHndl != NULL))
      {
        while ((inSize = fread(Cpybuf, 1, sizeof Cpybuf, FrmHndl)) > 0)
        {
          consPrefix("[+] ", consGre);
          printf("8K Block: %d\r", NBlox++);

          outSize = fwrite(Cpybuf, 1, inSize, TooHndl);
          if (outSize < inSize)
          {
            /****************************************************************/
            /* Somethingwent wrong - Show an error and quit                 */
            /****************************************************************/
            if (ferror(TooHndl))
            {
              if (binLog == 1)
                fprintf(LogHndl, "[!] Error Copying File (Output Error)\n");

              consPrefix("[!] ", consRed);
              printf("Error Copying File (Output Error)\n");
            }
            else
            {
              if (binLog == 1)
                fprintf(LogHndl, "[!] Error Copying File (Disk Full)\n");

              consPrefix("[!] ", consRed);
              printf("Error Copying File (Disk full)\n");
            }
            break;
          }

          fflush(stdout); //More PSExec Friendly

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
        _stat(tmpTooFile, &Toostat);
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
          consPrefix("[+] ", consGre);
          printf("Converging Mismatched TimeStamp(s)\n");

          if (binLog == 1)
            fprintf(LogHndl, "[+] Converging Mismatched TimeStamp(s)\n");

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
            consPrefix("[+] ", consGre);
            printf("File Owner Set (%s)\n", SidString);

            if (binLog == 1)
             fprintf(LogHndl, "[+] File Owner Set (%s)\n", SidString);
          }
          else
          {
            consPrefix("[*] ", consYel);
            printf("Can NOT Set Target File Owner(%s)\n", SidString);
            if (binLog == 1)
             fprintf(LogHndl, "[*] Can NOT Set Target File Owner (%s)\n", SidString);
          }
        }
        else
        {
          consPrefix("[*] ", consYel);
          printf("Could NOT Determine Source File Owner(Unknown)\n");

          if (binLog == 1)
            fprintf(LogHndl, "[*] Could NOT Determine Source File Owner (Unknown)\n");
        }


        /****************************************************************/
        /* MD5 The Files                                                */
        /****************************************************************/
        memset(MD5Tmp, 0, 255);
        FileMD5(tmpFrmFile);
        strncpy(MD5Tmp, MD5Out, 255);
      
        if (binLog == 1)
        {
          fprintf(LogHndl, "[+] Source File MD5.....: %s\n", MD5Out);
          fprintf(LogHndl, "[+] Source MetaData.....: %ld-%lld-%lld-%lld\n", Frmstat.st_size, Frmstat.st_ctime, Frmstat.st_atime, Frmstat.st_mtime);
        }
        consPrefix("[+] ", consGre);
        printf("Source File MD5.....: %s\n", MD5Out);

        consPrefix("[+] ", consGre);
        printf("Source MetaData.....: %ld-%lld-%lld-%lld\n", Frmstat.st_size, Frmstat.st_ctime, Frmstat.st_atime, Frmstat.st_mtime);

        _stat(tmpTooFile, &Toostat);
        FileMD5(tmpTooFile);
        if (binLog == 1)
        {
          fprintf(LogHndl, "[+] Destination File MD5: %s\n", MD5Out);
          fprintf(LogHndl, "[+] Destination MetaData: %ld-%lld-%lld-%lld\n", Toostat.st_size, Toostat.st_ctime, Toostat.st_atime, Toostat.st_mtime);
        }
        consPrefix("[+] ", consGre);
        printf("Destination File MD5: %s\n", MD5Out);

        consPrefix("[+] ", consGre);
        printf("Destination MetaData: %ld-%lld-%lld-%lld\n", Toostat.st_size, Toostat.st_ctime, Toostat.st_atime, Toostat.st_mtime);

        if (strnicmp(MD5Tmp, MD5Out, 255) != 0)
        {
          consPrefix("[!] ", consRed);
          printf("MD5 MisMatch!\n");
          if (binLog == 1)
           fprintf(LogHndl, "[!] MD5 MisMatch!\n");
        }

        if (Frmstat.st_size != Toostat.st_size)
        {
          consPrefix("[!] ", consRed);
          printf("Size Mismatch!\n");
          if (binLog == 1)
           fprintf(LogHndl, "[!] Size MisMatch!\n");
        }

        if (Frmstat.st_ctime != Toostat.st_ctime)
        {
          Old_CTime = localtime(&Frmstat.st_ctime);
          strftime(OldDate, 25, "%m/%d/%y@%H:%M:%S\0", Old_CTime);

          consPrefix("[!] ", consRed);
          printf("Create Time Mismatch! Actual Create Time: %s\n", OldDate);

          if (binLog == 1)
            fprintf(LogHndl, "[!] Create Time MisMatch! Actual Create Time: %s\n", OldDate);
        }

        if (Frmstat.st_mtime != Toostat.st_mtime)
        {
          Old_MTime = localtime(&Frmstat.st_mtime);
          strftime(OldDate, 25, "%m/%d/%y@%H:%M:%S\0", Old_MTime);

          consPrefix("[!] ", consRed);
          printf("Modify Time Mismatch! Actual Modify Time: %s\n", OldDate);

          if (binLog == 1)
            fprintf(LogHndl, "[!] Modify MisMatch! Actual Modify Time: %s\n", OldDate);
        }

        if (Frmstat.st_atime != Toostat.st_atime)
        {
          Old_ATime = localtime(&Frmstat.st_atime);
          strftime(OldDate, 25, "%m/%d/%y@%H:%M:%S\0", Old_ATime);

          consPrefix("[!] ", consRed);
          printf("Access Time Mismatch! Actual Access Time: %s\n", OldDate);

          if (binLog == 1)
            fprintf(LogHndl, "[!] Access MisMatch! Actual Access Time: %s\n", OldDate);
        }
      }
      else
      {
        if (binLog == 1)
          fprintf(LogHndl, "[!] Could Not Open File(s) for Copy\n");

        consPrefix("[!] ", consRed);
        printf("Could Not Open File(s) for Copy\n");
      }

      fflush(stdout); //More PSExec Friendly

    }

    fflush(stdout); //More PSExec Friendly

  }

  fflush(stdout); //More PSExec Friendly
  return 0;
}


/****************************************************************/
/* LZNT1 Copy/Decompress From, To, OutFile Size (for Padding)   */
/*                                                              */
/*  * LZNT1 Compressed Input - 64K Chunks (16 x 4K sections)    */
/*  * Pass Max File Size since the file can be Sparse           */
/*                                                              */
/****************************************************************/
int lznCopy(char *FrmFile, char *TooFile, ULONG TooSize)
{
  WORD chunk_hdr_test;
  NTSTATUS lastStatus;
  int deCompRC = 0; 

  ULONG n;
  size_t inSize ;
  PUCHAR InLzbuf ;  //Input LZNT1 Encoded
  PUCHAR UnLzbuf ;  //Output Decompresseed (UnLz) Data
  PUCHAR Wrkzbuf ;  //Working Space  
  ULONG  writLen ;  //How many bytes were written to the file
  ULONG  bytsLft ;  //How many bytes are left in the File

  int iLZNTSz = 65536 ;
  int NBlox = 0;

  char tmpFrmFile[4096];
  char tmpTooFile[4096];
  int iFileCount = 0;
  int iFileFound = 0;
  int TimeNotGood = 0;
  int setOwner = 0;

  FILE* FrmHndl;
  HANDLE HndlToo;

  DWORD dwRtnCode = 0;
  DWORD SecLen, LenSec;
  PSID pSidOwner = NULL;
  BOOL pFlag = FALSE;
  
  // Signature Checking Variables
  CHAR filetype[11] = "\0";


  /****************************************************************/
  /* Determine Chunk Size based on Cluster Size                   */
  /****************************************************************/
  if(bootb.SectorsPerCluster > 7 )
   iLZNTSz = 0x10000 ;  //4K Cluster (512 * 8) / 0x10000 Chunk 
  else   
  if(bootb.SectorsPerCluster > 3)
   iLZNTSz = 0x8000 ; //2K Cluster (512 * 4) / 0x8000 Chunk
  else   
  if(bootb.SectorsPerCluster > 1)
   iLZNTSz = 0x4000 ;  //1K Cluster (512 * 2) / 0x4000 Chunk
  else   
  if(bootb.SectorsPerCluster == 1)
   iLZNTSz = 0x2000 ;  //512Byte Cluster / 0x2000 Chunk



  /****************************************************************/
  /* Make Sure the File is Not There - Don't Overwrite!           */
  /****************************************************************/
  deCompRC = 0; //Assume All is well

  memset(tmpTooFile, 0, 4096);
  snprintf(tmpTooFile, 4090, "%s", TooFile);

  memset(tmpFrmFile, 0, 4096);
  snprintf(tmpFrmFile, 4090, "%s", FrmFile);


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

  if (iFileCount > 0)
  {
    fprintf(LogHndl, "[*] DeCompressed File Already Exists. \n     Renamed To: %s\n", tmpTooFile);
    consPrefix("[*] ", consYel);
    printf("Decompressed File Already Exists. \n     Renamed To: %s\n", tmpTooFile);
  }


  iFileFound = 1;  // Assume Yes, Found
  if (access(tmpFrmFile, 0) != 0)
  {
    iFileFound = 0; // Not Found

    fprintf(LogHndl, "[!] Source Compressed File Not Found: \n %s\n", tmpFrmFile);
    consPrefix("[!] ", consRed);
    printf("Source Compressed File Not Found: \n %s\n", tmpFrmFile);


    // Check for Sysnative edge case (running 32 bit on 64 bit)
    if (iNative == 0)
    {
      iFileFound = 1; //Wait... Maybe it's a file Redirect

      if(strnicmp(FrmFile+strlen(WinRoot), "\\System32\\", 10) == 0)
      {
        memset(tmpFrmFile, 0, 4096);
        sprintf(tmpFrmFile, "%s\\Sysnative\\%s\0", WinRoot, FrmFile+strlen(WinRoot)+10);

        fprintf(LogHndl, "[*] Non-Native Flag Has Been Detected - Trying Sysnative Redirection: \n %s\n", tmpFrmFile);
        consPrefix("[*] ", consYel);
        printf("Non-Native Flag Has Been Detected - Trying Sysnative Redirection: \n %s\n", tmpFrmFile);

        if (access(tmpFrmFile, 0) != 0)
        {
          iFileFound = 0; //No... Sorry... Not Sysnative

          fprintf(LogHndl, "[*] Sysnative Source Compressed File Also Not Found: \n %s\n", tmpFrmFile);
          consPrefix("[*] ", consYel);
          printf("Sysnative Source Compressed File Also Not Found: \n %s\n", tmpFrmFile);
          fflush(stdout); //More PSExec Friendly

          deCompRC =  1;
          return 1;
        }
        else
        {
          iFileFound = 1; // Yes... Substitution Successful

          fprintf(LogHndl, "[*] Sysnative Source Compressed File Found, Now Substituting.\n");
          consPrefix("[*] ", consYel);
          printf("Sysnative Source Compressed File Found, Now Substituting.\n");
          fflush(stdout); //More PSExec Friendly
        }
      }
      else
      {
        fflush(stdout); //More PSExec Friendly
        deCompRC =  1;
        return 1;
      }

    }

  }


  if(iFileFound == 1)
  {
    /****************************************************************/
    /* Get the original TimeStamps                                  */
    /****************************************************************/
    _stat(tmpFrmFile, &Frmstat);


    /****************************************************************/
    /* Get the SID (File Owner) of the file - Security Descripter   */
    /****************************************************************/
    gotOwner = 0;

    /****************************************************************/
    /* NOTE: Use Static Security Descriptor Buffer. Its Safer       */
    /****************************************************************/
    SecLen = 200;

    // Populate the Security Description Structure
    if (GetFileSecurity(tmpFrmFile, OWNER_SECURITY_INFORMATION, SecDesc, SecLen, &LenSec))
    {
      if (GetSecurityDescriptorOwner(SecDesc, &pSidOwner, &pFlag))
      {
        gotOwner = 1;
        convert_sid_to_string_sid(pSidOwner, SidString);
      }
    }


    /****************************************************************/
    /* Open Input File - Make sure we can read it!                  */
    /****************************************************************/
    FrmHndl = fopen(tmpFrmFile, "rb"); // Open From File
    if (FrmHndl == NULL)
    {
      consPrefix("[!] ", consRed);
      printf("Could Not Open Compressed File for Reading - File Decompress Bypassed.\n");
      fprintf(LogHndl, "[!] Could Not Open Compressed File for Reading - File Decompress Bypassed.\n");

      fflush(stdout); //More PSExec Friendly
      deCompRC = 2;
      return 2;
    }

    //Output Uncompressed File
    HndlToo = CreateFile((LPCSTR)TooFile, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (HndlToo == INVALID_HANDLE_VALUE)
    {
      consPrefix("[!] ", consRed);
      printf("Could Not Open UnCompressed Output File for Writing - File Decompress Bypassed.\n");
      fprintf(LogHndl, "[!] Could Not Open UnCompressed Output File for Writing - File Decompress Bypassed.\n");

      fflush(stdout); //More PSExec Friendly
      deCompRC = 3;
      return 3;
    }



    //Allocate the LZNT1 64K Buffers 
    // InLzbuf = Compressed Input
    // UnLzbuf = Decompressed Output
    // Wrkzbuf = 4K Working Buffer
    tot_byt_src = tot_byt_dst = 0;
    bytsLft = TooSize;

    InLzbuf  = (UCHAR *) malloc(iLZNTSz);
    UnLzbuf  = (UCHAR *) malloc(iLZNTSz);
    Wrkzbuf  = (UCHAR *) malloc(0x1000);

    //Start with Clean Memory
    memset(InLzbuf, 0, iLZNTSz);
    memset(UnLzbuf, 0, iLZNTSz);
    memset(Wrkzbuf, 0, 0x1000);


    // Did we allocate our Buffers OK?
    if (InLzbuf == NULL || UnLzbuf == NULL || Wrkzbuf == NUL)
    {
      consPrefix("[!] ", consRed);
      printf("LZNT1 - Buffer Allocation Error - File Decompress Bypassed.\n");
      fprintf(LogHndl, "[!] LZNT1 Buffer Allocation Error - File Decompress Bypassed.\n");

      free(InLzbuf);
      free(UnLzbuf);
      free(Wrkzbuf);

      fflush(stdout); //More PSExec Friendly
      fclose(FrmHndl);
      CloseHandle(HndlToo);

      deCompRC = 4;
      return 4;
    }


    while ((inSize = fread(InLzbuf, 1, iLZNTSz, FrmHndl)) > 0)
    {
      consPrefix("[+] ", consGre);
      printf("LZNT1 64K Block: %d\r", NBlox++);

      //Make sure we have a chunk Header 
      chunk_hdr_test = *(WORD *)(InLzbuf);
      if (!chunk_hdr_test) 
      {
        //Bad Chunk Header - Zero Out the Chunk (This is the Observed Windows Behavior)
        //May not always be bad, sometimes source data is all zeroes, usually at the end of the file //YK
        consPrefix("[!] ", consRed);
        printf("Invalid Chunk Header...  Zeroing Chunk: %d\n", NBlox);
        fprintf(LogHndl, "[!] Invalid Chunk Header...  Zeroing Chunk %d\n", NBlox);

        //Write out a 64K Chunk of Nulls
        writLen = iLZNTSz;

        //Sometimes we decompress more bytes than the FileSize.  So defer to Filesize!
        if (bytsLft < writLen)
         writLen = bytsLft;

        memset(UnLzbuf, 0, iLZNTSz);
        WriteFile(HndlToo, UnLzbuf, writLen, &n, 0);

        tot_byt_src += inSize ;
        tot_byt_dst += writLen ;
        bytsLft = TooSize-tot_byt_dst;

        //Start Next Round with Clean Memory
        memset(InLzbuf, 0, iLZNTSz);
        memset(Wrkzbuf, 0, 0x1000);

        deCompRC = 5;
      }
      else
      {
        lastStatus = lznt1_decompress(UnLzbuf, iLZNTSz, InLzbuf, inSize, 0, &writLen, Wrkzbuf);
        if (lastStatus == 0)
        {
          //Sometimes we decompress more bytes than the FileSize.  So defer to Filesize!
          if (bytsLft < writLen)
           writLen = bytsLft;

          WriteFile(HndlToo, UnLzbuf, writLen, &n, 0);

          tot_byt_src += inSize ;
          tot_byt_dst += writLen ;
          bytsLft = TooSize-tot_byt_dst;

          //Start Next Round with Clean Memory
          memset(InLzbuf, 0, iLZNTSz);
          memset(UnLzbuf, 0, iLZNTSz);
          memset(Wrkzbuf, 0, 0x1000);

        }
        else
        {
          consPrefix("[!] ", consRed);
          printf("Decompress RetCD: %08x Encountered in Chunk: %d - Zeroing Chunk.\n", lastStatus, NBlox);
          fprintf(LogHndl, "[!] Decompressed RetCD: %08x Encounterd in Chunk %d - Zeroing Chunk.\n", lastStatus, NBlox);

          //Write out a 64K Chunk of Nulls
          writLen = iLZNTSz;

          //Sometimes we decompress more bytes than the FileSize.  So defer to Filesize!
          if (bytsLft < writLen)
           writLen = bytsLft;

          memset(UnLzbuf, 0, iLZNTSz);
          WriteFile(HndlToo, UnLzbuf, writLen, &n, 0);

          tot_byt_src += inSize ;
          tot_byt_dst += writLen ;
          bytsLft = TooSize-tot_byt_dst;

          //Start Next Round with Clean Memory
          memset(InLzbuf, 0, iLZNTSz);
          memset(Wrkzbuf, 0, 0x1000);

          deCompRC = 6;
        }
      }
    }


    free(InLzbuf);
    free(UnLzbuf);
    free(Wrkzbuf);


    //For Some reason File around 15K or more always write 0 Bytes - Need to investigate this
    //For now: Deal with that here (Set Error Code so we can use OS Copy)
    if (tot_byt_dst < 1)
    {
      consPrefix("[!] ", consRed);
      printf("Decompress Error: 0 Bytes Were Decompressed.\n");
      fprintf(LogHndl, "[!] Decompress Error: 0 Bytes Were Decompressed.\n");

      deCompRC = 7;
    }


    if (bytsLft > 0)
    {
      //Debug Information - Check on Padding for Sparse File
      //consPrefix("[+] ", consGre);
      //printf("Padding out Sparse File: %lu Bytes.\n", bytsLft);
      //fprintf(LogHndl, "[!] Padding out Sparse File: %lu Bytes.\n", bytsLft);
      //End Debug Information

      Wrkzbuf  = (UCHAR *) malloc(bytsLft);
      memset(Wrkzbuf, 0, bytsLft);
      WriteFile(HndlToo, Wrkzbuf, bytsLft, &n, 0);
      free(Wrkzbuf);
    }

    // Close Everything and Set File Dates
    fflush(stdout); //More PSExec Friendly
    fclose(FrmHndl);
    CloseHandle(HndlToo);
  

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
    _stat(tmpTooFile, &Toostat);
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
      consPrefix("[+] ", consGre);
      printf("Converging Mismatched TimeStamp(s)\n");

      fprintf(LogHndl, "[+] Converging Mismatched TimeStamp(s)\n");

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
        consPrefix("[+] ", consGre);
        printf("File Owner Set (%s)\n", SidString);

        fprintf(LogHndl, "[+] File Owner Set (%s)\n", SidString);
      }
      else
      {
        consPrefix("[*] ", consYel);
        printf("Can NOT Set Target File Owner(%s)\n", SidString);
        fprintf(LogHndl, "[*] Can NOT Set Target File Owner (%s)\n", SidString);
      }
    }
    else
    {
      consPrefix("[*] ", consYel);
      printf("Could NOT Determine Source File Owner(Unknown)\n");
      fprintf(LogHndl, "[*] Could NOT Determine Source File Owner (Unknown)\n");
    }


    /****************************************************************/
    /* MD5 The Files - They obviously will not match                */
    /****************************************************************/
    memset(MD5Tmp, 0, 255);
    FileMD5(tmpFrmFile);
    strncpy(MD5Tmp, MD5Out, 255);
      
    fprintf(LogHndl, "[+] Source File MD5.....: %s\n", MD5Out);
    fprintf(LogHndl, "[+] Source MetaData.....: %ld-%lld-%lld-%lld\n", Frmstat.st_size, Frmstat.st_ctime, Frmstat.st_atime, Frmstat.st_mtime);
    consPrefix("[+] ", consGre);
    printf("Source File MD5.....: %s\n", MD5Out);

    consPrefix("[+] ", consGre);
    printf("Source MetaData.....: %ld-%lld-%lld-%lld\n", Frmstat.st_size, Frmstat.st_ctime, Frmstat.st_atime, Frmstat.st_mtime);

    _stat(tmpTooFile, &Toostat);
    FileMD5(tmpTooFile);
    fprintf(LogHndl, "[+] Destination File MD5: %s\n", MD5Out);
    fprintf(LogHndl, "[+] Destination MetaData: %ld-%lld-%lld-%lld\n", Toostat.st_size, Toostat.st_ctime, Toostat.st_atime, Toostat.st_mtime);

    consPrefix("[+] ", consGre);
    printf("Destination File MD5: %s\n", MD5Out);

    consPrefix("[+] ", consGre);
    printf("Destination MetaData: %ld-%lld-%lld-%lld\n", Toostat.st_size, Toostat.st_ctime, Toostat.st_atime, Toostat.st_mtime);


    /****************************************************************/
    /* Make Sure Times copied over OK                               */
    /****************************************************************/
    if (Frmstat.st_ctime != Toostat.st_ctime)
    {
      Old_CTime = localtime(&Frmstat.st_ctime);
      strftime(OldDate, 25, "%m/%d/%y@%H:%M:%S\0", Old_CTime);

      consPrefix("[!] ", consRed);
      printf("Create Time Mismatch! Actual Create Time: %s\n", OldDate);
      fprintf(LogHndl, "[!] Create Time MisMatch! Actual Create Time: %s\n", OldDate);
    }

    if (Frmstat.st_mtime != Toostat.st_mtime)
    {
      Old_MTime = localtime(&Frmstat.st_mtime);
      strftime(OldDate, 25, "%m/%d/%y@%H:%M:%S\0", Old_MTime);

      consPrefix("[!] ", consRed);
      printf("Modify Time Mismatch! Actual Modify Time: %s\n", OldDate);
      fprintf(LogHndl, "[!] Modify MisMatch! Actual Modify Time: %s\n", OldDate);
    }

    if (Frmstat.st_atime != Toostat.st_atime)
    {
      Old_ATime = localtime(&Frmstat.st_atime);
      strftime(OldDate, 25, "%m/%d/%y@%H:%M:%S\0", Old_ATime);

      consPrefix("[!] ", consRed);
      printf("Access Time Mismatch! Actual Access Time: %s\n", OldDate);
      fprintf(LogHndl, "[!] Access MisMatch! Actual Access Time: %s\n", OldDate);
    }


    fflush(stdout); //More PSExec Friendly


    // Only return egregious error codes (will cause an OS/API Copy to also happen)
    // Otherwise, it's likely to be OK - For our first implementation - Lets error on 6 and 7 to be safe
    //  Note: 6 appears to be OK (and possibly 7 too) - but err on the side of caution.
    if(deCompRC > 5)
     return deCompRC;
   else
    return 0;

  }
  else
  {
    fflush(stdout); //More PSExec Friendly
    return 1;
  }
}


/****************************************************************/
/* Raw NTFS Copy From, To                                       */
/****************************************************************/
int rawCopy(char *FrmFile, char *TooFile, int binLog)
{
  CHAR drive[] = "\\\\.\\C:";
  ULONG n;

  char Full_Fname[2048] = "\0";
  char From_Fname[2048] = "\0";
  char Tooo_Fname[2048] = "\0";
  int  Full_MFTID;
  int  SQL_MFT = 0;
  int  i;

  FILETIME File_Create, File_Access, File_Modify;
  char Text_FNCreDate[30] = "\0";
  char Text_FNAccDate[30] = "\0";
  char Text_FNModDate[30] = "\0";
  char Text_SICreDate[30] = "\0";
  char Text_SIAccDate[30] = "\0";
  char Text_SIModDate[30] = "\0";
  char Text_FileTyp[5] = "\0";
  char * pointEnd;
  char *Slash;

  DWORD SecLen, LenSec;
  PSID pSidOwner = NULL;
  BOOL pFlag = FALSE;

  int PrivSet = 0;
  int PrivOwn = 0;
  int PrivSec = 0;
  int PrivBac = 0;
  int PrivRes = 0;

  int DDRetcd = 0;
  int lzRetcd = 0;

  // Get The Drive Letter
  drive[4] = FrmFile[0];
  driveLetter[0] = FrmFile[0];
  sprintf(MFTDBFile, "%s\\%s-MFT.db\0", CachDir, driveLetter);

  //Check that we have a valid From format (x:\) - We need the Root Volume for this to work.
  if (strnicmp(FrmFile+1, ":\\\0", 2) != 0)
  {
    fprintf(LogHndl, "[+] Invalid From File Format: %s\n", FrmFile);

    consPrefix("[+] ", consGre);
    printf("Invalid From File Format: %s\n", FrmFile);
    fflush(stdout); //More PSExec Friendly
    return 1;
  }


  // Get the handle to the primary partition/volume/physical disk
  hVolume = CreateFile(drive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
  if (hVolume == INVALID_HANDLE_VALUE)
  {
    consPrefix("[!] ", consRed);
    printf("Could not open the Volume for Raw Access. Error: %u\n", GetLastError());
    fprintf(LogHndl, "[!] Could not open the Volume for Raw Access. Error: %u\n", GetLastError());
    fflush(stdout); //More PSExec Friendly
    return 1;
  }

  
  // Reads data from the specified input/output (I/O) device - volume / physical disk
  if (ReadFile(hVolume, &bootb, sizeof bootb, &n, 0) == 0)
  {
    consPrefix("[!] ", consRed);
    printf("Could not read Volume for Raw Access. Error: %u\n", GetLastError());
    fprintf(LogHndl, "[!] Could not read the Volume for Raw Access. Error: %u\n", GetLastError());
    fflush(stdout); //More PSExec Friendly
    return 1;
  }


  //Load MFT Info
  LoadMFT();
  fflush(stdout); //More PSExec Friendly

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
    consPrefix("[!] ", consRed);
    printf("Could Not Open MFT Working Database : %s\n", MFTDBFile);
    fprintf(LogHndl, "[!] Could Not Open MFT Working Database: %s\n", MFTDBFile);
    fflush(stdout); //More PSExec Friendly
    return 1;
  }


  if (SQL_MFT == 1)
  {
    // ORIGINAL Optimizations to make SQLite DB access as fast as possible
    // Note: I have disabled most of them because they take up too much memory
    //       I have opted for slower, less memory itensive options so AChoir 
    //       could run on more (older) machines.
    //dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA cache_size=4000", NULL, NULL, &errmsg);
    //dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA synchronous=NORMAL", NULL, NULL, &errmsg);
    //dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA journal_mode=MEMORY", NULL, NULL, &errmsg);
    dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA journal_mode=OFF", NULL, NULL, &errmsg);
    //dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA temp_store=MEMORY", NULL, NULL, &errmsg);


    SpinLock = 0;
    while ((dbMrc = sqlite3_exec(dbMFTHndl, "CREATE TABLE FileNames (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, FullFileName)", 0, 0, &errmsg)) != SQLITE_OK)
    {
      if (dbMrc == SQLITE_BUSY)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_LOCKED)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_ERROR)
      {
        consPrefix("[!] ", consRed);
        printf("Error Creating FileNames Table\n%s\n", errmsg);
        fprintf(LogHndl, "[!] Error Creating FileNames Table\n%s\n", errmsg);
        
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

    SpinLock = 0;
    while ((dbMrc = sqlite3_exec(dbMFTHndl, "CREATE TABLE MFTFiles (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, MFTPrvID INTEGER, FileName, FileDateTyp, FNCreDate, FNAccDate, FNModDate, SICreDate, SIAccDate, SIModDate, Compress INTEGER)", 0, 0, &errmsg)) != SQLITE_OK)
    {
      if (dbMrc == SQLITE_BUSY)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_LOCKED)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_ERROR)
      {
        consPrefix("[!] ", consRed);
        printf("Error Creating MFTFiles Table\n%s\n", errmsg);
        fprintf(LogHndl, "[!] Error Creating MFTFiles Table\n%s\n", errmsg);

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


    while ((dbMrc = sqlite3_exec(dbMFTHndl, "CREATE TABLE MFTDirs (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, MFTPrvID INTEGER, DirsName)", 0, 0, &errmsg)) != SQLITE_OK)
    {
      if (dbMrc == SQLITE_BUSY)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_LOCKED)
        Sleep(100); // In windows.h
      else
      if (dbMrc == SQLITE_ERROR)
      {
        consPrefix("[!] ", consRed);
        printf("Error Creating MFTDirs Table\n%s\n", errmsg);
        fprintf(LogHndl, "[!] Error Creating MFTDirs Table\n%s\n", errmsg);

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

    sqlite3_exec(dbMFTHndl, "CREATE INDEX MFTDirs_IDX ON MFTDirs(MFTRecID ASC)", 0, 0, &errmsg);


    // The primary partition supplied else
    // default C:\ will be used
    FindActive();

    fflush(stdout); //More PSExec Friendly

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
        iIsCompressed = 0 ;
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
          else
          if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "Compress", 8) == 0)
          {
            iIsCompressed = sqlite3_column_int(dbMFTStmt, dbi);
          }
        }


        for (i = (int) strlen(Full_Fname); i > 0; i--)
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

        /****************************************************************/
        /* NOTE: Use a Static Security Descriptor Buffer.  Its Safer    */
        /****************************************************************/
        SecLen = 200;

        // Populate the Security Description Structure
        if (GetFileSecurity(Full_Fname, OWNER_SECURITY_INFORMATION, SecDesc, SecLen, &LenSec))
        {
          if (GetSecurityDescriptorOwner(SecDesc, &pSidOwner, &pFlag))
          {
            gotOwner = 1;
            convert_sid_to_string_sid(pSidOwner, SidString);
          }
        }

        consPrefix("\n[+] ", consGre);
        printf("Raw Copying MFT File: %s (%d)\n", Full_Fname + i + 1, Full_MFTID);
        printf("    %s\n", Full_Fname);

        fprintf(LogHndl, "\n[+] Raw Copying MFT File: %s (%d)\n", Full_Fname + i + 1, Full_MFTID);
        fprintf(LogHndl, "    %s\n", Full_Fname);


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
              consPrefix("     Status: ", consRed);
			        printf("FN/SI Not Matched\n");
			        fprintf(LogHndl, "     Status: FN/SI Not Matched\n");
			      }
            else
			      {
              consPrefix("     Status: ", consGre);
			        printf("FN/SI Matched\n");
			        fprintf(LogHndl, "     Status: FN/SI Matched\n");
			      }
		      }
		      else
		      {
            consPrefix("     Status: ", consYel);
			      printf("FN Only\n");
			      fprintf(LogHndl, "     Status: FN Only\n");
		      }

        }
        else
        if (DDRetcd == 2)
         DDRetcd = 0; //Yeah - It's kludgy, but RC=2 is just a way to exit out - Reset it to be a 0 (Everything is OK)
        else
        {
		      // We had an Error Copying Raw
          consPrefix("\n[!] ", consRed);
		      printf("Error Encountered Copying the file.  Internal Return Code: %d\n", DDRetcd);
		      fprintf(LogHndl, "Error Encountered Copying the file.  Internal Return Code: %d\n", DDRetcd);
        }


        /****************************************************************/
        /* Tell us if the File is Compressed.  It's nice to know        */
        /****************************************************************/
        if(iIsCompressed == 1)
        {
          fprintf(LogHndl, "[*] Raw Copied File Was Detected as COMPRESSED\n");
          consPrefix("[*] ", consYel);
          printf("Raw Copied File Was Detected as  COMPRESSED!\n");
       }


        /****************************************************************/
        /* Check if we should DeCompressthe file (SetNCP > 0)           */
        /*  NODCMP(0) = Don't Decompress                                */
        /*  DECOMP(1) = LZNT1 Decompress                                */
        /*  RAWONLY(1) = LZNT1 Decompress                               */
        /*  OSCOPY(1) = On LZNT1 Decompress Error - Do an API/OS Copy   */
        /****************************************************************/
        if((iIsCompressed == 1) && (setNCP > 0))
        {
          /*******************************************************************/
          /* Add (LZ) to From_Fname - And Rename it                          */
          /*******************************************************************/
          memset(From_Fname, 0, 2048) ;
          memset(Tooo_Fname, 0, 2048) ;
          strncpy(From_Fname, last_Fname, 2000) ;
          strncpy(Tooo_Fname, last_Fname, 2000) ;
          strcat(From_Fname, "(LZ)") ;

          fprintf(LogHndl, "[*] LZNT1 Rename:\n     From: %s\n     To: %s\n", Tooo_Fname, From_Fname);
          consPrefix("[*] ", consYel);
          printf("LZNT1 Rename:\n     From: %s\n     To: %s\n", Tooo_Fname, From_Fname);

          rename(Tooo_Fname, From_Fname);


          /*******************************************************************/
          /* Now Decompress into Original Name                               */
          /*******************************************************************/
          fprintf(LogHndl, "[*] LZNT1 Decompress:\n     In: %s\n     Out: %s\n", From_Fname, Tooo_Fname);
          consPrefix("[*] ", consYel);
          printf("LZNT1 Decompress:\n     In: %s\n     Out: %s\n", From_Fname, Tooo_Fname);

          lzRetcd = lznCopy(From_Fname, Tooo_Fname, maxDataSize /*last_rawdLen*/); //YK


          /****************************************************************/
          /* Error Encountered Decompressing - Should we try an OCSOPY?   */
          /****************************************************************/
          if((setNCP == 2) && (lzRetcd !=0 || DDRetcd != 0))
          {
            fprintf(LogHndl, "[*] LZNT1 Decompress Encountered Errors, Trying Standard OS Copy to create Decompressed version.\n");
            consPrefix("[*] ", consYel);
            printf("LZNT1 Decompress Encountered Errors, Trying Standard OS Copy to create Decompressed version.\n");


            /*******************************************************************/
            /* Add (LX) to From_Fname - And Rename it (eXreacted)              */
            /*******************************************************************/
            memset(From_Fname, 0, 2048) ;
            strncpy(From_Fname, last_Fname, 2000) ;
            strcat(From_Fname, "(LX)") ;

            fprintf(LogHndl, "[*] LZNT1 Rename:\n     From: %s\n     To: %s\n", Tooo_Fname, From_Fname);
            consPrefix("[*] ", consYel);
            printf("LZNT1 Rename:\n     From: %s\n     To: %s\n", Tooo_Fname, From_Fname);

            rename(Tooo_Fname, From_Fname);


            /*******************************************************************/
            /* Identify the Filename from the Full_Fname and create Tooo_Fname */
            /*******************************************************************/
            memset(Tooo_Fname, 0, 2048) ;
            strncpy(Tooo_Fname, TooFile, 2000) ;
            if ((Slash = strrchr(Full_Fname, '\\')) != NULL)
            {
              if (strlen(Slash) > 2)
               strcat(Tooo_Fname, Slash);
              else
               strcat(Tooo_Fname, "NewFile\0");
            }
            else
             strcat(Tooo_Fname, "NewFile\0");

            binCopy(Full_Fname, Tooo_Fname, binLog);

          }

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
          consPrefix("[*] ", consYel);
          printf("SQLite Loop Detected");
          break;
        }
      }
    }

    fflush(stdout); //More PSExec Friendly

  }

  sqlite3_finalize(dbMFTStmt);
  sqlite3_free(dbMQuery);

  sqlite3_close(dbMFTHndl);
  CloseHandle(hVolume);

  //UnLoad MFT Info - Disabled for now - Sometimes causes a crash
  //UnloadMFT();

  fflush(stdout); //More PSExec Friendly
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
long consInput(char *consString, int conLog, int conHide)
{
  if(conLog == 1)
    fprintf(LogHndl, "INP: [%s] ", consString);

  consPrefix("INP: ", consBlu);
  printf("%s", consString);
  fflush(stdout); //More PSExec Friendly

  memset(Conrec, 0, 255);
  fgets(Conrec, 251, stdin);
  strtok(Conrec, "\n");
  strtok(Conrec, "\r");

  //strtok doesnt work on a blank string - So Add this little gem
  if((Conrec[0] == CrLf[0]) || (Conrec[0] == CrLf[1]))
   Conrec[0] = CrLf[2];


  /****************************************************************/
  /* If our input is too long, clear the rest over 250 chars      */
  /****************************************************************/
  if (strlen(Conrec) > 249)
  {
    if(conLog == 1)
      fprintf(LogHndl, "[!] Input Truncated!\n");

    consPrefix("[!] ", consRed);
    printf("Input Truncated!\n");

    while ((getKey = getchar()) != '\n' && getKey != EOF);
  }

  if(conLog == 1)
  {
    if(conHide == 1)
     fprintf(LogHndl, "*Redacted*\n");
    else
     fprintf(LogHndl, "%s\n", Conrec);
  }

  fflush(stdout); //More PSExec Friendly
  return 0;
}



/****************************************************************/
/* Map a Remote Drive                                           */
/****************************************************************/
long mapsDrive(char *mapString, int mapLog)
{
  memset(Conrec, 0, 255);
  if (strlen(mapString) < 1)
  {
    consPrefix("[?] ", consYel);
    consInput("Map: Server\\Share> ", mapLog, 0);
  }
  else
    strncpy(Conrec, mapString, 254);


  iGoodMap = 0;
  while (iGoodMap == 0)
  {
    if(mapLog == 1)
      fprintf(LogHndl, "MAP: %s\n", Conrec);

    consPrefix("MAP: ", consBlu);
    printf("%s\n", Conrec);

    netRes.dwType = RESOURCETYPE_DISK;
    netRes.lpRemoteName = Conrec;

    // Fresh Mapping to Server Share
    netRC = WNetUseConnection(NULL, &netRes, inPass, inUser, Flags, szConnection, &ConnectSize, &ConnectResult);

    if (netRC != NO_ERROR)
    {
      consPrefix("[!] ", consRed);
      printf("Error Mapping Resource: %s\n\n", Conrec);

      if (mapLog == 1)
        fprintf(LogHndl, "[!] Error Mapping Resource: %s\n\n", Conrec);

      consPrefix("[?] ", consYel);
      printf("Please Re-Enter Server\\Drive or \"quit\".\n");

      memset(Conrec, 0, 255);
      consPrefix("[?] ", consYel);
      consPrefix("MAP: ", consBlu);
      consInput("Server\\Share> ", mapLog, 0);

      if (strnicmp(Conrec, "quit", 4) == 0)
      {
        consPrefix("[!] ", consRed);
        printf("Program Exit Requested.\n");
 
        if (mapLog == 1)
        {
          fprintf(LogHndl, "[!] Program Exit Requested.\n");
          cleanUp_Exit(1);
        }

        fflush(stdout); //More PSExec Friendly
        exit (1);

      }
    }
    else
    {
      iGoodMap = 1;
      consPrefix("[+] ", consGre);
      printf("Successfully Mapped %s to drive %s\n", Conrec, szConnection);

      if (mapLog == 1)
        fprintf(LogHndl, "[+] Successfully Mapped %s to drive %s\n", Conrec, szConnection);

      strncpy(MapDrive, szConnection, 3);

      sprintf(BACQDir, "%s\\%s\0", szConnection, ACQName);
      sprintf(CachDir, "%s\\%s\\Cache\0", szConnection, ACQName);

      fflush(stdout); //More PSExec Friendly
      return 0;
    }
  }

  fflush(stdout); //More PSExec Friendly
  return 0;

}


/****************************************************************/
/* Create a Local Share (For Remote Acq)                        */
/****************************************************************/
long netLocalShare(char *netServer, char *netSharePath, char *netShareName, int shrLog)
{
  char xnetSharePath[255] ;
  char xnetShareName[255] ;
  char xnetSharePass[255] ;

  wchar_t w_netSharePath[520];
  wchar_t w_netShareName[520];
  wchar_t w_netSharePass[50];
  wchar_t w_netServer[520];

  LPWSTR lpWnetSharePath = w_netSharePath;
  LPWSTR lpWnetShareName = w_netShareName;
  LPWSTR lpWnetSharePass = w_netSharePass;
  LPWSTR lpWnetServer = w_netServer;

  int  pwdCtr = 0;
  

  //Generate a Random Password - Just to make sure 
  memset(xnetSharePass, 0, 20);
  srand((unsigned)time(NULL));

  for(pwdCtr = 0; pwdCtr < 14; pwdCtr++)
   xnetSharePass[pwdCtr] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[rand() % 62];
 
  //Shhhh...  Don't tell anyone the Share Password.
  //printf("Password: %s\n", xnetSharePass);


  memset(xnetSharePath, 0, 255);
  memset(xnetShareName, 0, 255);

  strncpy(xnetSharePath, netSharePath, 254);
  strncpy(xnetShareName, netShareName, 254);

  memset(w_netSharePath, 0, 520);
  memset(w_netShareName, 0, 520);
  memset(w_netSharePass, 0, 50);

  if (strlen(xnetSharePath) < 1)
  {
    memset(Conrec, 0, 255);
    consPrefix("[?] ", consYel);
    consInput("Full Path Of Share> ", shrLog, 0);
    strncpy(xnetSharePath, Conrec, 254);
  }

  if (strlen(xnetShareName) < 1)
    strncpy(xnetShareName, "ACh-Rmt\0\0\0", 10);


  iGoodShr = 0;
  while (iGoodShr == 0)
  {
    if(shrLog == 1)
      fprintf(LogHndl, "SHR: %s -> %s\n", xnetSharePath, xnetShareName);

    consPrefix("SHR: ", consBlu);
    printf("%s -> %s\n", xnetSharePath, xnetShareName);

    // convert to LPWSTR for the API...  Sigh...
    MultiByteToWideChar(0, 0, xnetSharePath, 512, w_netSharePath, 254);
    MultiByteToWideChar(0, 0, xnetShareName, 512, w_netShareName, 254);
    MultiByteToWideChar(0, 0, xnetSharePass, 40, w_netSharePass, 20);

    netShr.shi2_netname = lpWnetShareName;
    netShr.shi2_type = STYPE_DISKTREE; // disk drive
    netShr.shi2_remark = L"Local Share Created By AChoir for Remote Acquisition";
    netShr.shi2_permissions = ACCESS_ALL;  
    netShr.shi2_max_uses = 4;
    netShr.shi2_current_uses = 0;
    netShr.shi2_path = lpWnetSharePath;
    //netShr.shi2_passwd = NULL;
    netShr.shi2_passwd = lpWnetSharePass;
 
    // Call the NetShareAdd() function, specifying level 2. 
    netShrRC = NetShareAdd(NULL, 2, (LPBYTE) &netShr, &netShrErr);

    if (netShrRC != 0)
    {
      consPrefix("[!] ", consRed);
      printf("Error Creating Local Share on %s: %s -> %s\n", netServer,xnetSharePath, xnetShareName);
      consPrefix("[!] ", consRed);
      printf("Error: %u\tParmErr=%u\n\n", netShrRC, netShrErr);

      if (shrLog == 1)
      {
        fprintf(LogHndl, "Error Creating Local Share on %s: %s -> %s\n", netServer, xnetSharePath, xnetShareName);
        fprintf(LogHndl, "Error: %u\tParmErr=%u\n\n", netShrRC, netShrErr);
      }

      consPrefix("[?] ", consYel);
      printf("Please Re-Enter Full Directory Path to Share or \"quit\".\n");

      memset(Conrec, 0, 255);
      consPrefix("[?] ", consYel);
      consPrefix("SHR: ", consBlu);
      consInput("Full Path Of Share> ", shrLog, 0);
      strncpy(xnetSharePath, Conrec, 254);

      if (strnicmp(Conrec, "quit", 4) == 0)
      {
        consPrefix("[!] ", consRed);
        printf("Program Exit Requested.\n");
 
        if (shrLog == 1)
        {
          fprintf(LogHndl, "[!] Program Exit Requested.\n");
          cleanUp_Exit(1);
        }

        fflush(stdout); //More PSExec Friendly
        exit (1);

      }
    }
    else
    {
      iGoodShr = 1;
      consPrefix("[+] ", consGre);
      printf("Successfully Created Share on %s: %s -> %s\n", netServer, xnetSharePath, xnetShareName);

      if (shrLog == 1)
        fprintf(LogHndl, "[+] Successfully Created Share on %s: %s -> %s\n", netServer, xnetSharePath, xnetShareName);

      fflush(stdout); //More PSExec Friendly
      return 0;
    }
  }

  fflush(stdout); //More PSExec Friendly
  return 0;

}


/****************************************************************/
/* Create a Local Share (For Remote Acq)                        */
/****************************************************************/
long netShareDel(char *netShareName, int shrLog)
{
  wchar_t w_netShareName[520];
  LPWSTR lpWnetShareName = w_netShareName;

  if (strlen(netShareName) < 1)
    strncpy(netShareName, "ACh-Rmt\0\0\0", 10);

  MultiByteToWideChar(0, 0, netShareName, 512, w_netShareName, 254);

  // Call the NetShareDel() function
  netShrRC = NetShareDel(NULL, w_netShareName, 0);

  if (netShrRC != NERR_Success)
  {
    consPrefix("[!] ", consRed);
    printf("Error (%d) Deleting Local Share: %s\n", netShrRC, netShareName);

    if (shrLog == 1)
     fprintf(LogHndl, "Error (%d) Deleting Local Shares: %s\n", netShrRC, netShareName);
  }
  else
  {
    consPrefix("[+] ", consGre);
    printf("Successfully Deleted Share: %s\n", netShareName);

    if (shrLog == 1)
      fprintf(LogHndl, "[+] Successfully Deleted Share: %s\n", netShareName);

    fflush(stdout); //More PSExec Friendly
    return 0;
  }

  fflush(stdout); //More PSExec Friendly
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
    sprintf(FullDateTime, "%02d/%02d/%04d - %02d:%02d:%02d",
      showlocal->tm_mon + 1, showlocal->tm_mday, (showlocal->tm_year + 1900),
      showlocal->tm_hour, showlocal->tm_min, showlocal->tm_sec);
  }
  else
  {
    consPrefix("[+] ", consGre);
    printf("%s: %02d/%02d/%04d - %02d:%02d:%02d\n", showText,
      showlocal->tm_mon + 1, showlocal->tm_mday, (showlocal->tm_year + 1900),
      showlocal->tm_hour, showlocal->tm_min, showlocal->tm_sec);

    // Only Log if we have opened the Log File.
    if(iLogOpen == 1)
      fprintf(LogHndl, "[+] %s: %02d/%02d/%04d - %02d:%02d:%02d\n", showText,
        showlocal->tm_mon + 1, showlocal->tm_mday, (showlocal->tm_year + 1900),
        showlocal->tm_hour, showlocal->tm_min, showlocal->tm_sec);
  }

  fflush(stdout); //More PSExec Friendly

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
        fprintf(LogHndl, "[+] USB WriteProtect Key: Off\n");
        consPrefix("[+] ", consGre);
        printf("USB WriteProtect Key: Off\n");
      }
      else
      {
        fprintf(LogHndl, "[+] USB WriteProtect Key: On\n");
        consPrefix("[+] ", consGre);
        printf("USB WriteProtect Key: On\n");
      }
    }
    else
    if (ReadK == ERROR_FILE_NOT_FOUND)
    {
      fprintf(LogHndl,"[*] USB WriteProtect Key Is Empty (Off)\n");
      consPrefix("[*] ", consYel);
      printf("USB WriteProtect Key Is Empty (Off)\n");
    }
    else
    {
      fprintf(LogHndl, "[!] Error Reading USB Write Protect Key!\n");
      consPrefix("[!] ", consRed);
      printf("Error Reading USB Write Protect Key!\n");
    }

    // No Need to Set it if already set 
    if (numUSB == USBOnOff)
      gotSet = 1;
    else
    {
      if (USBOnOff == 0)
      {
        fprintf(LogHndl, "[+] Resetting WriteProtect Key To: Off\n");
        consPrefix("[+] ", consGre);
        printf("Resetting WriteProtect Key To: Off\n");
      }
      else
      {
        fprintf(LogHndl, "[+] Resetting WriteProtect Key To: On\n");
        consPrefix("[+] ", consGre);
        printf("Resetting WriteProtect Key To: On\n");
      }


      MakeK = RegSetValueEx(phkResult, "WriteProtect", 0, REG_DWORD, (LPBYTE)&USBOnOff, sizeof(DWORD));
      if (MakeK == ERROR_SUCCESS)
      {
        gotSet = 1;

        fprintf(LogHndl, "[+] USB WriteProtect Key Set Succesfully\n");
        consPrefix("[+] ", consGre);
        printf("USB WriteProtect Key Set Succesfully\n");
        
        if (USBOnOff == 1)
        {
          fprintf(LogHndl, "\n[+] Important Note: ONLY NEW ATTACHED DRIVES WILL BE WRITE PROTECTED.\n");
          consPrefix("\n[+] ", consGre);
          printf("Important Note: ONLY NEW ATTACHED DRIVES WILL BE WRITE PROTECTED.\n");
        }
      }
      else
      {
        fprintf(LogHndl, "\n[!] * * * USB WriteProtect Key WAS NOT Set Succesfully * * *\n");
        consPrefix("\n[!] ", consRed);
        printf("* * * USB WriteProtect Key WAS NOT Set Succesfully * * *\n");
      }
    }
  }
  else 
  if (OpenK == ERROR_FILE_NOT_FOUND)
  {
    fprintf(LogHndl, "[!] Could Not Open/Create USB WriteProtect Key\n");
    consPrefix("[!] ", consRed);
    printf("Could Not Open/Create USB WriteProtect Key\n");
  }
  else 
  if (OpenK == ERROR_ACCESS_DENIED)
  {
    fprintf(LogHndl, "[!] USB WriteProtect Key Access Denied\n");
    consPrefix("[!] ", consRed);
    printf("USB WriteProtect Key Access Denied\n");

    if (iIsAdmin == 0)
    {
      fprintf(LogHndl, "[!] USB WriteProtect Key Requires ADMIN Priveleges\n");
      consPrefix("[!] ", consRed);
      printf("USB WriteProtect Key Requires ADMIN Priveleges\n");
    }
  }
  else
  {
    fprintf(LogHndl, "[!] USB WriteProtect Key Registry Error: %d\n", OpenK);
    consPrefix("[!] ", consRed);
    printf("USB WriteProtect Key Registry Error: %d\n", OpenK);
  }


  if (gotSet == 0)
  {
    getLoop = 0;

    fprintf(LogHndl, "\n[!] Error Setting USB Write Protect Key!\n  Enter \"c\" to continue or \"x\" To Exit\n");
    consPrefix("\n[!] ", consRed);
    printf("Error Setting USB Write Protect Key!\n  Enter \"c\" to continue or \"x\" To Exit\n");

    while (getLoop == 0)
    {
      getKey = getchar();
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

        fflush(stdout); //More PSExec Friendly
        cleanUp_Exit(0);
        exit(0) ;
      }

      fflush(stdout); //More PSExec Friendly

    }

    fflush(stdout); //More PSExec Friendly

  }

  fflush(stdout); //More PSExec Friendly

}



void cleanUp_Exit(int exitRC)
{
  /****************************************************************/
  /* Cleanup                                                      */
  /****************************************************************/
  if (access(ForFile, 0) == 0)
   unlink(ForFile);

  if (access(ForDisk, 0) == 0)
   unlink(ForDisk);


  if (iHtmMode == 1)
  {
    fprintf(HtmHndl, "</td><td align=right>\n");
    fprintf(HtmHndl, "<button onclick=\"window.history.forward()\">&gt;&gt;</button>\n");
    fprintf(HtmHndl, "</td></tr></table></Center>\n<p>\n");
    fprintf(HtmHndl, "<iframe name=AFrame style=\"padding:2px;border:3px Lavender solid;\"  height=75%% width=98%% scrolling=auto src=file:./></iframe>\n");
    fprintf(HtmHndl, "</p>\n</body></html>\n");

    fclose(HtmHndl);
  }


  if (iRunMode == 1)
  {
    fprintf(LogHndl, "[+] Setting All Artifacts to Read-Only.\n");

    consPrefix("[+] ", consGre);
    printf("Setting All Artifacts to Read-Only.\n");

    sprintf(TempDir, "%s\\*.*\0", BACQDir);
    ListDir(TempDir, "ROS");
  }


  /****************************************************************/
  /* All Done with Acquisition                    `               */
  /****************************************************************/
  printf("\n"); // Make a blank Line.
  showTime("Acquisition Completed");

  if (iXitCmd == 1)
  {
    fprintf(LogHndl, "\nXIT: Queuing Exit Program:\n %s\n", XitCmd);
    consPrefix("\nXIT: ", consBlu);
    printf("Queuing Exit Program:\n %s\n", XitCmd);
  }

  /****************************************************************/
  /* Make a Copy of the Logfile in the ACQDirectory               */
  /****************************************************************/
  if (access(BACQDir, 0) == 0)
  {
    iCPS = 0; //ALWAYS Copy LogFile

    fprintf(LogHndl, "\n[+] Copying Log File...\n");

    consPrefix("\n[+] ", consGre);
    printf("Copying Log File...\n");

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

  consPrefix("[+] ", consGre);
  printf("Exit Return Code: %d\n", exitRC);

  fflush(stdout); //More PSExec Friendly
  //exit(exitRC) ;
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

  // Check for a Compressions size - Good Clue this file is compressed
  if(attr->CompressionUnit == 4)
   iIsCompressed = 1;


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
  PUSHORT usa;
  PUSHORT sector;

  usa = PUSHORT(Padd(file, file->Ntfs.UsaOffset));
  sector = PUSHORT(file);

  for (iFix = 1; iFix < file->Ntfs.UsaCount; iFix++)
  {
    sector[255] = usa[iFix];
    sector += 256;
  }
}


VOID ReadSectorX(ULONGLONG sector, PVOID buffer)
{
  ULARGE_INTEGER offset;
  OVERLAPPED overlap = { 0 };
  ULONG n;

  offset.QuadPart = sector * bootb.BytesPerSector;
  overlap.Offset = offset.LowPart;
  overlap.OffsetHigh = offset.HighPart;

  readRetcd = ReadFile(hVolume, buffer, bootb.BytesPerSector, &n, &overlap);

  if (readRetcd == 0)
  {
    consPrefix("\n[!] ", consRed);
    printf("Error Reading Sector!  Cannot Process This Volume in RAW Mode!\n");
  }

  fflush(stdout); //More PSExec Friendly

}


VOID ReadSectorToMem(ULONGLONG sector, ULONG count, PVOID buffer)
{
  ULARGE_INTEGER offset;
  OVERLAPPED overlap = { 0 };
  ULONG n;

  offset.QuadPart = sector * bootb.BytesPerSector;
  overlap.Offset = offset.LowPart;
  overlap.OffsetHigh = offset.HighPart;

  readRetcd = ReadFile(hVolume, buffer, count * bootb.BytesPerSector, &n, &overlap);

  if (readRetcd == 0)
  {
    consPrefix("[!] ", consRed);
    printf("Error Reading Sector To Memory!  Cannot Process This Volume in RAW Mode!\n");
  }

  fflush(stdout); //More PSExec Friendly

}


VOID ReadSectorToDisk(ULONGLONG sector, ULONG count, PVOID buffer)
{
  ULARGE_INTEGER offset;
  OVERLAPPED overlap = { 0 };
  ULONG n, cCount;
  int iShowSector ;

  FILE* SectHndl;
  char SectFile[1024] = "C:\\AChoir\\Cache\\Sectors.tmp\0";

  sprintf(SectFile, "%s\\%s\\Cache\\Sectors.tmp\0", BaseDir, ACQName);

  // If useDiskOrMem == 1 (<2) It is the first cluster run (new Temp File)
  //  if it is > 1 then Append the cluster run.
  if(useDiskOrMem < 2)
    SectHndl = fopen(SectFile, "wb");
  else
    SectHndl = fopen(SectFile, "ab");


  if (SectHndl != NULL)
  {
    iShowSector = 0;
    for(cCount = 0; cCount < count; cCount++)
    {
      offset.QuadPart = (sector + cCount) * bootb.BytesPerSector;
      overlap.Offset = offset.LowPart;
      overlap.OffsetHigh = offset.HighPart;

      readRetcd = ReadFile(hVolume, buffer, bootb.BytesPerSector, &n, &overlap);

      if (readRetcd == 0)
      {
        consPrefix("\n[!] ", consRed);
        printf("Error Reading Sector To Disk!  Cannot Process This Volume in RAW Mode!\n");
        cCount = count;    // Bypass the rest
        fclose(SectHndl);  // Close
        continue;          // Loop back to top
      }

      fwrite(buffer, 1, n, SectHndl);

      iShowSector++;
      if(iShowSector > 5000)
      {
        iShowSector = 0;
        consPrefix("[+] ", consGre);
        printf("Cluster Run: %d - Sector: %llu\r", useDiskOrMem, sector+cCount);
      }
    }

    fclose(SectHndl);
    useDiskOrMem++;
  }
  else
  {
    consPrefix("[!] ", consRed);
    printf("Error Creating Sector Cache File!\n");
  }

  fflush(stdout); //More PSExec Friendly

}


VOID ReadLCN(ULONGLONG lcn, ULONG count, PVOID buffer)
{
  if(useDiskOrMem == 0)
   ReadSectorToMem(lcn * bootb.SectorsPerCluster, count * bootb.SectorsPerCluster, buffer);
  else
   ReadSectorToDisk(lcn * bootb.SectorsPerCluster, count * bootb.SectorsPerCluster, buffer);
}


// Non resident attributes
VOID ReadExternalAttribute(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, ULONG count, PVOID buffer)
{
  ULONGLONG lcn, runcount;
  ULONG readcount, left, n;
  PUCHAR bytes = PUCHAR(buffer);

  totbytes = totdata = 0;
  for (left = count; left > 0; left -= readcount)
  {
    FindRun(attr, vcn, &lcn, &runcount);
    readcount = ULONG(min(runcount, left));
    n = readcount * bootb.BytesPerSector * bootb.SectorsPerCluster;

    if (lcn == 0)
     memset(bytes, 0, n);
    else
    {
      if(useDiskOrMem == 0)
        ReadLCN(lcn, readcount, bytes);
      else 
        ReadLCN(lcn, readcount, buffer);
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


ULONG AttributeLengthCompressed(PATTRIBUTE attr)
{
  return attr->Nonresident == FALSE ?
    PRESIDENT_ATTRIBUTE(attr)->ValueLength :
    ULONG(PNONRESIDENT_ATTRIBUTE(attr)->CompressedSize);
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


VOID ReadAttributeX(PATTRIBUTE attr, PVOID buffer)
{
  PRESIDENT_ATTRIBUTE rattr = NULL;
  PNONRESIDENT_ATTRIBUTE nattr = NULL;
  ULONGLONG lcn, runcount;


  if (attr->Nonresident == FALSE)
  {
    rattr = PRESIDENT_ATTRIBUTE(attr);
    memcpy(buffer, Padd(rattr, rattr->ValueOffset), rattr->ValueLength);
  }
  else
  {
    nattr = PNONRESIDENT_ATTRIBUTE(attr);
    FindRun(nattr, ULONG(nattr->LowVcn), &lcn, &runcount);

    ReadSectorX(lcn * bootb.SectorsPerCluster, buffer);
  }
}


VOID ReadVCN(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, ULONGLONG vcn, ULONG count, PVOID buffer)
{
  PATTRIBUTE attrlist = NULL;
  PNONRESIDENT_ATTRIBUTE attr = PNONRESIDENT_ATTRIBUTE(FindAttributeX(file, type, 0, 0));

  if (attr == 0 || (vcn < attr->LowVcn || vcn > attr->HighVcn))
  {
    // Support for huge files
    attrlist = FindAttributeX(file, AttributeAttributeList, 0, 0);

    consPrefix("[!] ", consRed);
    printf("Dropping into Debug Break\n");
    DebugBreak();
  }

  ReadExternalAttribute(attr, vcn, count, buffer);

  fflush(stdout); //More PSExec Friendly

}


VOID ReadFileRecord(ULONG index, PFILE_RECORD_HEADER file)
{
  PUCHAR p;
  ULONG clusters;
  ULONGLONG vcn;

  clusters = bootb.ClustersPerFileRecord;
  if (clusters > 0x80)
    clusters = 1;
  
  p = (UCHAR *) malloc(bootb.BytesPerSector * bootb.SectorsPerCluster * clusters)  ;
  if(p == NULL) 
   MemAllocErr("MFT Record Buffer") ;

  vcn = ULONGLONG(index) * BytesPerFileRecord / bootb.BytesPerSector / bootb.SectorsPerCluster;

  ReadVCN(MFT, AttributeData, vcn, clusters, p);
  LONG m = (bootb.SectorsPerCluster * bootb.BytesPerSector / BytesPerFileRecord) - 1;
  ULONG n = m > 0 ? (index & m) : 0;

  memcpy(file, p + n * BytesPerFileRecord, BytesPerFileRecord);

  free(p);

  FixupUpdateSequenceArray(file);
}


VOID LoadMFT()
{
  //consPrefix("\n[+] ", consGre);
  //printf("Locating the MFT for Raw Disk Access...\n");
  //fprintf(LogHndl, "\n[+] Locating the MFT for Raw Disk Access...\n");

  BytesPerFileRecord = bootb.ClustersPerFileRecord < 0x80
    ? bootb.ClustersPerFileRecord* bootb.SectorsPerCluster
    * bootb.BytesPerSector : 1 << (0x100 - bootb.ClustersPerFileRecord);

  MFT = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);

  ReadSectorToMem((bootb.MftStartLcn)*(bootb.SectorsPerCluster), (BytesPerFileRecord) / (bootb.BytesPerSector), MFT);

  if (readRetcd == 0)
  {
    consPrefix("[!] ", consRed);
    printf("Cannot Access NTFS Volume...  Bypassing...\n");
    fprintf(LogHndl, "[!] Cannot Access NTFS Volume...  Bypassing...\n");
    
   fflush(stdout); //More PSExec Friendly
   return; // Don't do anything else - We cant Acccess this Volume!
  }
  
  if (MFT->Ntfs.Type != 'ELIF')
  {
    consPrefix("[!] ", consRed);
    printf("Not An NTFS Volume...  Bypassing...\n");
    fprintf(LogHndl, "[!] Not An NTFS Volume...  Bypassing...\n");

    readRetcd = 0;
    fflush(stdout); //More PSExec Friendly
    return;
  }
  
  FixupUpdateSequenceArray(MFT);

  fflush(stdout); //More PSExec Friendly
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


int FindActive()
{
  PATTRIBUTE attr = FindAttributeX(MFT, AttributeBitmap, 0, 0);
  PATTRIBUTE attr2 = attr;
  PATTRIBUTE attr3 = attr;
  PUCHAR bitmap = new (std::nothrow) UCHAR[AttributeLengthAllocated(attr)];

  PFILENAME_ATTRIBUTE name = NULL;
  PFILENAME_ATTRIBUTE name2 = NULL;
  PSTANDARD_INFORMATION name3 = NULL;

  char TempFlag[10] = "\0";

  char Full_Fname[2048] = "\0";
  char Ftmp_Fname[2048] = "\0";
  char Str_Temp1[15] = "\0";
  char Str_Temp2[15] = "\0";
  int Str_Len, Max_Files, Short_Len;
  int Progress, ProgUnit;
  int File_RecNum, Dir_PrevNum, File_RecID;
  int MoreDirs;
  int iLinkCount, iLink, iGotOne;


  char Text_CreDate[30] = "\0";
  char Text_AccDate[30] = "\0";
  char Text_ModDate[30] = "\0";
  char Text_DateTyp[5] = "\0";
  char Str_Numbers[40] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\0\0\0";

  // Did we allocate bitmap OK?
  if(bitmap == NULL) 
   MemAllocErr("Cluster Search Buffer") ;

  LCNType = 0; // Read Attribute Not File
  useDiskOrMem = maxMemExceed = 0; //Default to Memory
  ReadAttribute(attr, bitmap);

  ULONG n = AttributeLength(FindAttributeX(MFT, AttributeData, 0, 0)) / BytesPerFileRecord;
  ProgUnit = n / 50;

  dbrc = sqlite3_exec(dbMFTHndl, "begin", 0, 0, &errmsg);

  consPrefix("MFT: ", consBlu);
  printf("Parsing Active Files from MFT...\n     ooooooooooo+oooooooooooo|oooooooooooo+ooooooooooo\r     ");
  fflush(stdout); //More PSExec Friendly

  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
  Progress = Max_Files = 0;
  for (ULONG i = 0; i < n; i++)
  {
    Progress++;
    if (Progress > ProgUnit)
    {
      dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);
      dbrc = sqlite3_exec(dbMFTHndl, "begin", 0, 0, &errmsg);

      printf(".");
      fflush(stdout); //More PSExec Friendly
      Progress = 0;
    }

    if (!bitset(bitmap, i))
      continue;

    LCNType = 0 ;
    ReadFileRecord(i, file);

    if (file->Ntfs.Type == 'ELIF' && (file->Flags == 1 || file->Flags == 3))
    {
      // YK - adding check for only Active (not deleted) entries
      if (file->Flags & 1 == 0)
        continue;
      // See How Many Links we have - Make sure we have at least two (Short & Long FN)
      iLinkCount = file->LinkCount;
      if(iLinkCount < 1)
       iLinkCount = 1 ;

      // Bump Through Attributes and Add them to the SQLite Table
      //  Note: Save the Short Name & Length in case it is the only one
      iGotOne = Short_Len = 0;
      memset(Str_Short, 0, 256);
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
        {
          //Type 2 is a Short FN - Save it, in case we only have this FN. This is an ODD
          // Edge case, where the Short FN is the ONLY FN (Track this via variable iGotOne)
          Short_Len = int(name->NameLength);
          wcstombs(Str_Short, name->Name, Short_Len);
          Str_Short[Short_Len] = '\0'; // Null Terminate the String... Sigh...
          continue;
        }


        Str_Len = int(name->NameLength);
        wcstombs(Str_Temp, name->Name, Str_Len);
        Str_Temp[Str_Len] = '\0'; // Null Terminate the String... Sigh...
      

        // Lets Grab The SI Attribute for SI File Dates (Cre/Acc/Mod)
        attr3 = FindAttributeX(file, AttributeStandardInformation, 0, 0);
        if (attr3 != 0)
        {
          name3 = PSTANDARD_INFORMATION(Padd(attr3, PRESIDENT_ATTRIBUTE(attr3)->ValueOffset));

          // Check to see if Compress Bit is on in the FileAttributes Field. //YK- moved to StdInfo, this gives correct current value of compressed
          if (name3->FileAttributes & (1 << ULONG(11)))
            iIsCompressed = 1;
          else
            iIsCompressed = 0;
        }

        if (file->Flags == 1)
        {
          // Active File Entry 
          iGotOne = 1;
          Max_Files++;

          if (attr3 == 0)
            dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileDateTyp, FNCreDate, FNAccDate, FNModDate, SICreDate, SIAccDate, SIModDate, Compress) VALUES ('%ld', '%ld', '%q', 'FN', '%llu', '%llu', '%llu', '0', '0', '0', '%ld')\0",
              i, int(name->DirectoryFileReferenceNumber), Str_Temp,
              ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime),
              ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime),
              iIsCompressed);
          else
            dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileDateTyp, FNCreDate, FNAccDate, FNModDate, SICreDate, SIAccDate, SIModDate, Compress) VALUES ('%ld', '%ld', '%q', 'SI', '%llu', '%llu', '%llu', '%llu', '%llu', '%llu', '%ld')\0",
              i, int(name->DirectoryFileReferenceNumber), Str_Temp,
              ULONGLONG(name3->CreationTime), ULONGLONG(name3->LastAccessTime), ULONGLONG(name3->LastWriteTime),
              ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime),
              iIsCompressed);
        }
        else
        {
          // Active Directory Entries
          iGotOne = 1;
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
            consPrefix("[!] ", consRed);
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


      /*****************************************************************/
      /* See if we wrote anything for this record.  If not, there may  */
      /*  may only be a Short FN - Which we typically ignore.  So go   */
      /*  ahead and write out the ShortFN - This is especially         */
      /*  critical if it is a Directory - so we dont break the chain   */
      /*  ... Chaiiin, Keep us together...  Runnin in the shadow...    */
      /*****************************************************************/
      if (iGotOne == 0)
      {
        //Nothing Written - Probably the Short FN Only Edge Case
        if (Short_Len > 0)
        {
          // Lets Grab The SI Attribute for SI File Dates (Cre/Acc/Mod)
          attr3 = FindAttributeX(file, AttributeStandardInformation, 0, 0);
          if (attr3 != 0)
           name3 = PSTANDARD_INFORMATION(Padd(attr3, PRESIDENT_ATTRIBUTE(attr3)->ValueOffset));


          if (file->Flags == 1)
          {
            // Active File Entry 
            iGotOne = 1;
            Max_Files++;

            if (attr3 == 0)
              dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileDateTyp, FNCreDate, FNAccDate, FNModDate, SICreDate, SIAccDate, SIModDate, Compress) VALUES ('%ld', '%ld', '%q', 'FN', '%llu', '%llu', '%llu', '0', '0', '0', '%ld')\0",
                i, int(name->DirectoryFileReferenceNumber), Str_Short,
                ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime),
                ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime),
                iIsCompressed);
            else
              dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileDateTyp, FNCreDate, FNAccDate, FNModDate, SICreDate, SIAccDate, SIModDate, Compress) VALUES ('%ld', '%ld', '%q', 'SI', '%llu', '%llu', '%llu', '%llu', '%llu', '%llu', '%ld')\0",
                i, int(name->DirectoryFileReferenceNumber), Str_Short,
                ULONGLONG(name3->CreationTime), ULONGLONG(name3->LastAccessTime), ULONGLONG(name3->LastWriteTime),
                ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime),
                iIsCompressed);
          }
          else
          {
            // Active Directory Entries
            iGotOne = 1;
            dbMQuery = sqlite3_mprintf("INSERT INTO MFTDirs (MFTRecID, MFTPrvID, DirsName) VALUES ('%ld', '%ld', '%q')\0", i, int(name->DirectoryFileReferenceNumber), Str_Short);
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
              consPrefix("[!] ", consRed);
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

      fflush(stdout); //More PSExec Friendly

    }

    fflush(stdout); //More PSExec Friendly

  }


  // Commit Before we build the Searchable Index
  dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);


  Progress = 0;
  ProgUnit = Max_Files / 50;

  // Begin - To speed up performance
  dbrc = sqlite3_exec(dbMFTHndl, "begin", 0, 0, &errmsg);
  wprintf(L"\n     Building Full Path Searchable Index...\n     ooooooooooo+oooooooooooo|oooooooooooo+ooooooooooo\r     ");


  /************************************************************/
  /* Expand out all the Files+Dirs for WildCard Searching     */
  /************************************************************/
  dbrc = sqlite3_prepare(dbMFTHndl, "select * from MFTFiles", -1, &dbMFTStmt, 0);
  if (dbrc != SQLITE_OK)
  {
    consPrefix("[!] ", consRed);
    printf("MFTErr: Could Not Read MFT Database: %s\n", MFTDBFile);
    MFT_Status = 2;
    fflush(stdout); //More PSExec Friendly
    return 2;
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
      consPrefix("[!] ", consRed);
      printf("MFTErr: MFT Database Error: %s\n", sqlite3_errmsg(dbMFTHndl));
      MFT_Status = 2;
      fflush(stdout); //More PSExec Friendly
      return 2;
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
          consPrefix("[!] ", consRed);
          printf("Error Adding Entry to FileNames Table\n%s\n", errmsg);
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
        dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);
        dbrc = sqlite3_exec(dbMFTHndl, "begin", 0, 0, &errmsg);

        printf(".");
        fflush(stdout); //More PSExec Friendly
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


  delete[] bitmap;
  delete[] file;

  fflush(stdout); //More PSExec Friendly

  return 0;
}


int DumpDataII(ULONG index, CHAR* filename, CHAR* outdir, FILETIME ToCreTime, FILETIME ToModTime, FILETIME ToAccTime, int binLog, int Append)
{
  PUCHAR bufD;
  PUCHAR bufA;
  FILE* SectHndl;
  char SectFile[1024] = "C:\\AChoir\\Cache\\Sectors.tmp\0";
  size_t inSize ;
  //size_t outSize;
  size_t totSect, difSect ;

  PATTRIBUTE attrlist = NULL;
  PATTRIBUTE_LIST attrdata = NULL;

  PATTRIBUTE attr = NULL;
  HANDLE hFile = NULL;
  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
  ULONG n;

  FILETIME ftCreate, ftAccess, ftWrite;
  LARGE_INTEGER ftSize;

  CHAR Tooo_Fname[2048] = "\0";
  int setOwner = 0;
  int iFileCount = 0;
  long iDataSize = 0;

  PNONRESIDENT_ATTRIBUTE nonresattr = NULL;
  PATTRIBUTE_LIST attrdatax = NULL;
  ULONG MaxOffset, MaxDataSize, MaxRawsz, MaxCmprs;
  USHORT LastOffset;
  long pointData;
  //ULONG attrLen, dataLen, rawdLen, cmprLen, writLen, leftSpars;
  ULONG attrLen, dataLen, rawdLen, cmprLen;

  int gotData, i, DDRetcd;
 
  // Signature Checking Variables
  CHAR filetype[11] = "\0";
  char *dotPos;


  iDepth++;

  //Sanity Check - We should not have Attribute List Within a Data Record
  if(iDepth > 2)
  {
    if (binLog == 1)
      fprintf(LogHndl, "[+] Recursion Too Deep - Ignoring Additional Recursion...\n");

    consPrefix("[+] ", consGre);
    printf("Recursion Too Deep - Ignoring Additional Recursion...\n");

    delete[] file;
    fflush(stdout); //More PSExec Friendly
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
      fprintf(LogHndl, "\n[+] Appending Data (Multiple Cluster Runs).\n");

    consPrefix("\n[+] ", consGre);
    printf("Appending Data (Multiple Cluster Runs).\n");
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
        fprintf(LogHndl, "[+] Destination File Already Exists. \n     Renamed To: %s\n", Tooo_Fname);

      consPrefix("[+] ", consGre);
      printf("Destination File Already Exists. \n     Renamed To: %s\n", Tooo_Fname);
    }
  }

  fflush(stdout); //More PSExec Friendly

  LCNType = 0;
  useDiskOrMem = maxMemExceed = 0; //Reset Default to Memory

  ReadFileRecord(index, file);

  if (file->Ntfs.Type != 'ELIF')
  {
    consPrefix("[!] ", consRed);
    printf("Not a Valid MFT Record...  Bypassing...\n");
    fprintf(LogHndl, "[!] Not a Valid MFT Record...  Bypassing...\n");

    delete[] file;
    fflush(stdout); //More PSExec Friendly
    return 1;
  }


  // Look for Attribute Data (0x80)
  attr = FindAttributeX(file, AttributeData, 0, 0);
  if (attr == 0)
  {
    // Look for Attribute Data (0x20)
    attrlist = FindAttributeX(file, AttributeAttributeList, 0, 0);
    if (attrlist != 0)
    {
      fileIsFrag = 1;
      consPrefix("\n[+] ", consGre);
      printf("File is Fragmented ...  Parsing the Attribute List...\n");
      fprintf(LogHndl,"\n[+] File is Fragmented... Parsing the Attribute List...\n");

      // Read the attribute list - Physical Size and Logical Size
      //  We use Physical size to READ the clusters and Logical Size to WRITE the new file
      MaxRawsz = AttributeLengthDataSize(attrlist);
      MaxOffset = AttributeLengthAllocated(attrlist);
      MaxCmprs = AttributeLengthCompressed(attrlist);


      // If its a compressed file, used the CompressedSize.
      if(iIsCompressed == 1)
      {
        strncpy(cIsCompressed, "(Compressed)\0", 13);
        //Test: Remove all Compress Sizes and Set To same as Uncompress
        //      LZNT1 appears to pad each 64K block chunk, making file size the same whether compressed or not
        //MaxDataSize = MaxCmprs ;
        MaxDataSize = MaxRawsz ;  //Test Using Actual Size
      }
      else
      {
        strncpy(cIsCompressed, "             \0", 13);
        MaxDataSize = MaxRawsz ;
      }

      bufA  = (UCHAR *) malloc(MaxOffset);

      // Did we allocate our Record oK?
      if(bufA == NULL) 
       MemAllocErr("Attribute Buffer") ;


      LCNType = 0; // Read Attribute Not File
      useDiskOrMem = maxMemExceed = 0; //Default to Memory
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

        if(LastOffset > MaxOffset)
        {
          consPrefix("[!] ", consRed);
          printf("No MFT File Attribute List Found...  Bypassing...\n");
          fprintf(LogHndl, "[!] No MFT File Attribute List Found...  Bypassing...\n");

          free(bufA);
          delete[] file;
          fflush(stdout); //More PSExec Friendly
          return 1 ;
        }


        // Go dump Data from Attribute Data Record (0x80)
        if (attrdata->AttributeType == AttributeData)
        {
          pointData = (LONG)attrdata->FileReferenceNumber; // it should be 6 bytes not 4  // YK

          if(gotData == 0)
          {
            //printf("Now looking at MFT Record: %lu", pointData);
            DDRetcd = DumpDataII(pointData, filename, outdir, ToCreTime, ToModTime, ToAccTime, binLog, 0);
            iDepth--;    //We Returned 

            gotData = 1;

            if (DDRetcd == 1)
            {
              free (bufA);
              delete[] file;
              return 1;
            }
          }
          else
          {
            DDRetcd = DumpDataII(pointData, filename, outdir, ToCreTime, ToModTime, ToAccTime, binLog, 1);
            iDepth--;    //We Returned 

            if (DDRetcd == 1)
            {
              free (bufA);
              delete[] file;
              return 1;
            }
          }
        }
      }

      fileIsFrag = 0;

      delete[] file;
      free (bufA);
    }
    else
    {
      consPrefix("[!] ", consRed);
      printf("No MFT File Attribute Data Found...  Bypassing...\n");
      fprintf(LogHndl, "[!] No MFT File Attribute Data Found...  Bypassing...\n");
    }

    fflush(stdout); //More PSExec Friendly
    //return 1; 
    return 2; //Everything is OK, but this is nested (0X80) - So return an RC to exit out.

  }
  else
  {
    //Try to get the file size
    // If it is 0 - See if we are in Append and Get the number of bytes
    //  Left in the File (leftSize)

    // YK - adding check for resident $DATA attribute
    if (attr->Nonresident == FALSE) {
        rawdLen = AttributeLengthDataSize(attr);
        if (iIsCompressed == 1)
            iIsCompressed = 0;  // if data is only in MFT (resident), it is not compressed (even if compression is ON)
    }
    // YK edit, Data size will only be available if LowestVCN==0, adding check for that here
    else if (PNONRESIDENT_ATTRIBUTE(attr)->LowVcn == 0) {
        rawdLen = AttributeLengthDataSize(attr);
        attrLen = AttributeLengthAllocated(attr);
        //Test: Remove all Compress Sizes and Set To same as Uncompress
        //      LZNT1 appears to pad each 64K block chunk, making file size the same whether compressed or not
        //cmprLen = AttributeLengthCompressed(attr);
        cmprLen = AttributeLengthAllocated(attr);  //Test setting the InFile Compression size to the whole Buffer Size 
    }

    //Global Last Data Length - Used to pass to LZNCopy Routine for the Size check (Sparse Data)
    last_rawdLen = rawdLen;

    //Global Last File Name - Used to pass to LZNCopy Routine for the Output/Input File Name
    memset(last_Fname, 0, 2048);
    strncpy(last_Fname, Tooo_Fname, 2040);


    // If the File is Compressed - Use Compression Size.
    if(iIsCompressed == 1)
    {
      strncpy(cIsCompressed, "(Compressed)\0", 13);
      //Test: Remove all Compress Sizes and Set To same as Uncompress
      //      LZNT1 appears to pad each 64K block chunk, making file size the same whether compressed or not
      //dataLen = cmprLen ;
      dataLen = rawdLen ;  //Test using actual Length
    }
    else
    {
      strncpy(cIsCompressed, "            \0", 13);
      dataLen = rawdLen ;
    }


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
    // If File exceeds Max Memory, Cache the Extraction
    maxMemExceed = useDiskOrMem = 0;
    if (attrLen > maxMemBytes)
    {
      maxMemExceed = 1 ;
      useDiskOrMem = 1 ;
    }

    
    LCNType = 1;   // Read Actual File Clusters into buf
    iNCSFound = 0; // Default to NOT Found

    // For NCP: it's ALWAYS found, for NCS: do the compare
    if(iNCS == 0)
     iNCSFound = 1;
    else
    if(iNCS == 1)
    {
      /****************************************************************/
      /* If we are doing an NCS - Read the First Cluster and compare  */
      /*  to the Signature Table entries                              */
      /****************************************************************/
      ClustZero  = (UCHAR *) malloc(bootb.BytesPerSector * bootb.SectorsPerCluster)  ;
      if(ClustZero == NULL) 
       MemAllocErr("Cluster Search Buffer") ;
      else
       memset(ClustZero, 0, bootb.BytesPerSector * bootb.SectorsPerCluster);

      ReadAttributeX(attr, ClustZero);

      // Start with a clean slate
      memset(tmpSig, 0, iSigSize);

      // Convert n Bytes into n*2 Hex Chars
      for (i=0; i < (iSigSize-1)/2; i++)
      {
        sprintf(tmpSig+(i*2), "%02x", ClustZero[i]);
      }

      // No Longer Needed.
      if (ClustZero != NULL)
       free(ClustZero);

      // Parse Out the FileType for Signature Checking
      memset(filetype, 0, 11);
      dotPos = strrchr(filename, '.') ;

      if(dotPos !=NULL)
       strncpy(filetype, dotPos + 1, 10);


      // Compare with the Signature and FileType Tables
      for (i=0; i < iSigCount; i++)
      {
        if((strnicmp(tmpSig, SigTabl+(i*iSigSize), SizTabl[i]) == 0) && (strlen(SigTabl+(i*iSigSize)) > 0))
        {
          iNCSFound = 1;

          consPrefix("     (Sig) ", consGre);
          printf("Header Signature Match Found in File (%s)\n", tmpSig);
          fprintf(LogHndl, "     (Sig)Header Signature Match Found in File (%s)\n", tmpSig);
          break;
        }

        if((strnicmp(filetype, TypTabl+(i*iTypSize), iTypSize) == 0) && (strlen(filetype) > 0))
        {
          iNCSFound = 1;
          consPrefix("     (Sig) ", consGre);
          printf("File Extention Match Found (%s)\n", filetype);
          fprintf(LogHndl, "     (Sig)File Extention Match Found (%s)\n", filetype);
          break;
        }
      }

      fflush(stdout); //More PSExec Friendly


      if(iNCSFound == 0)
      {
        consPrefix("     (Sig) ", consRed);
        printf("No Signature Match in File - File Copy Bypassed.\n");
        fprintf(LogHndl, "     (Sig)No Signature Match in File - File copy Bypassed.\n");

        delete[] file;
        fflush(stdout); //More PSExec Friendly
        return 1;
      }
    }

    // Complete the copy if we are doing an NCP: - or if the NCS: Signature was found
    if (iNCSFound == 1)
    {
      // Print Information about file for Verification
      if(gotOwner != 1)
       sprintf(SidString, "Could Not Get SID\0");

      printf("     (In)SID: %s\n", SidString);
      fprintf(LogHndl, "     (In)SID: %s\n", SidString);

      printf("     (In)Time: %llu - %llu - %llu\n", File_CreDate, File_AccDate, File_ModDate);
      fprintf(LogHndl, "     (In)Time: %llu - %llu - %llu\n", File_CreDate, File_AccDate, File_ModDate);


      if(maxMemExceed == 0)
      {
        // Fit the Whole File in a buffer
        bufD  = (UCHAR *) malloc(attrLen)  ;

        //Set Entire Buffer to =x0 - This is in case the file is SPARSE (end of file will be =x0s)
        //This is especially important for LZNT1 Decompressed files
        memset(bufD, 0, attrLen);
      }
      else
      {
        // MaxMem Exceeded! Just Use a Cluster at a Time - Also Show us the size.
        bufD  = (UCHAR *) malloc(bootb.BytesPerSector * bootb.SectorsPerCluster)  ;

        printf("     (In)Size: %lu ", dataLen);
        consPrefix(cIsCompressed, consYel);
        printf("\n");

        consPrefix("\n[+] ", consGre);
        printf("File Exceeds Max Memory Size...  Disk Caching Sectors...\n");

        if (binLog == 1)
        {
          fprintf(LogHndl, "     (In)Size: %lu %s\n", dataLen, cIsCompressed);
          fprintf(LogHndl, "\n[+] File Exceeds Max Memory Size...  Disk Caching Sectors...\n");
        }
      }

      fflush(stdout); //More PSExec Friendly

      // Did we allocate our Data Buffer OK?
      if(bufD == NULL) 
       MemAllocErr("Data Buffer") ;

      ReadAttribute(attr, bufD);

      iDataSize = maxDataSize;

      //In cases where the file is Resident use maxDataSize
      if(totdata > maxDataSize)
       totdata = maxDataSize;


      //Now show the iData Size since we didn't show the dataLen
      if(maxMemExceed != 1)
      {
        printf("     (In)Size: %ld ", iDataSize);
        consPrefix(cIsCompressed, consYel);
        printf("                         \n");
      
        if (binLog == 1)
          fprintf(LogHndl, "     (In)Size: %ld %s                        \n", iDataSize, cIsCompressed);
      }

      consPrefix("\n[+] ", consGre);
      printf("Dumping Raw Data to FileName:\n    %s\n", Tooo_Fname);
  
      if (binLog == 1)
        fprintf(LogHndl, "\n[+] Dumping Raw Data to FileName:\n    %s\n", Tooo_Fname);

      fflush(stdout); //More PSExec Friendly

 
      if(Append == 1)
        hFile = CreateFile((LPCSTR)Tooo_Fname, FILE_APPEND_DATA, 0, 0, OPEN_ALWAYS, 0, 0);
      else
        hFile = CreateFile((LPCSTR)Tooo_Fname, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);

      if (hFile == INVALID_HANDLE_VALUE)
      {
        if (binLog == 1)
          fprintf(LogHndl, "[!] Error Creating File: %u\n", GetLastError());

        consPrefix("[!] ", consRed);
        printf("Error Creating File: %u\n", GetLastError());

        free(bufD);
        delete[] file;
        fflush(stdout); //More PSExec Friendly
        return 1;
      }

      if(useDiskOrMem == 0)
      {
        // Write the File From the memory Buffer
        if (WriteFile(hFile, bufD, totdata, &n, 0) == 0)
        {
          if (binLog == 1)
            fprintf(LogHndl, "[!] Error Writing File: %u\n", GetLastError());

          consPrefix("[!] ", consRed);
          printf("Error Writing File: %u\n", GetLastError());

          free(bufD);
          delete[] file;
          fflush(stdout); //More PSExec Friendly
          return 1;
        }
      }  
      else
      {
        // Copy the Cache Data to the Actual File
        sprintf(SectFile, "%s\\%s\\Cache\\Sectors.tmp\0", BaseDir, ACQName);
        SectHndl = fopen(SectFile, "rb");

        totSect = 0 ;
        if (SectHndl != NULL)
        {
          while ((inSize = fread(bufD, 1, bootb.BytesPerSector, SectHndl)) > 0)
          {
            totSect += inSize;

            // Check for Memory Slack and subtract it out
            if (totSect > totdata)
            {
              // Sometimes we can be in negative territory if we have extra File Slack Sectors
              // When that happens, ignore the File Slack Sectors (in the Cluster)
              difSect = totSect - totdata ;
              if(difSect >= bootb.BytesPerSector)
               continue;
              else
               inSize -= difSect; // Subtract the delta from our Last Sector Read.
            }

            if (WriteFile(hFile, bufD, (DWORD) inSize, &n, 0) == 0)
            {
              if (binLog == 1)
                fprintf(LogHndl, "[!] Error Writing File: %u\n", GetLastError());

              consPrefix("[!] ", consRed);
              printf("Error Writing File: %u\n", GetLastError());


              free(bufD);
              delete[] file;
              fflush(stdout); //More PSExec Friendly
              return 1;
            }
          }

          fclose(SectHndl);
          unlink(SectFile);

        }
      }

      fflush(stdout); //More PSExec Friendly

      //Set the File Times
      if(SetFileTime(hFile, &ToCreTime, &ToAccTime, &ToModTime) == 0)
      {
        consPrefix("[!] ", consRed);
        printf("Error Setting File Time!\n");
      }

      //Read it back out to Verify
      if(GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite) == 0)
      {
        consPrefix("[!] ", consRed);
        printf("Error Retrieving File Time!\n");
      }

      //Read it back out to Verify
      if(GetFileSizeEx(hFile, &ftSize) == 0)
      {
        consPrefix("[!] ", consRed);
        printf("Error Getting File Size!\n");
      }

      if(CloseHandle(hFile) == 0)
      {
        consPrefix("[!] ", consRed);
        printf("Error Closing File!\n");
      }

      fflush(stdout); //More PSExec Friendly

      useDiskOrMem = maxMemExceed = 0; //Reset to Memory

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
            fprintf(LogHndl, "[*] Could NOT Set Target File Owner.\n");

          consPrefix("[*] ", consYel);
          printf("Could NOT Set Target File Owner.\n");
        }
      }
      else
      {
        if (binLog == 1)
          fprintf(LogHndl, "[*] Could NOT Determine Source File Owner(Unknown)\n");

        consPrefix("[*] ", consYel);
        printf("Could NOT Determine Source File Owner(Unknown)\n");
      }

      fflush(stdout); //More PSExec Friendly

      free(bufD);


      /****************************************************************/
      /* MD5 The Files                                                */
      /****************************************************************/
      _stat(Tooo_Fname, &Toostat); // Debug - Sometimes we hang on _stat!

      FileMD5(Tooo_Fname);

      if (binLog == 1)
      {
        fprintf(LogHndl, "     (out)Time: %llu - %llu - %llu\n", ftCreate, ftAccess, ftWrite);
        fprintf(LogHndl, "     (out)Size: %llu %s\n", ftSize.QuadPart, cIsCompressed);
        fprintf(LogHndl, "     (out)File MD5: %s\n", MD5Out);
      }
      printf("     (out)Time: %llu - %llu - %llu\n", ftCreate, ftAccess, ftWrite);
      printf("     (out)Size: %llu ", ftSize.QuadPart);
      consPrefix(cIsCompressed, consYel);
      printf("\n");
      printf("     (out)File MD5: %s\n", MD5Out);

      if ((CompareFileTime(&ToCreTime, &ftCreate) != 0) || (CompareFileTime(&ToAccTime, &ftAccess) != 0) || (CompareFileTime(&ToModTime, &ftWrite) != 0))
      {
        consPrefix("\n[*] ", consYel);
        printf("File TimeStamp MisMatch\n");

        if (binLog == 1)
          fprintf(LogHndl, "\n[*] File TimeStamp MisMatch\n");
      }

      //Check if ANY of the File Size Calculations (mis)Match
      if ((iDataSize != Toostat.st_size)  && (dataLen != ftSize.QuadPart))
      {
        if(fileIsFrag == 1)
        {
           consPrefix("\n[+] ", consGre);
           printf("File Size Fragmentation - More Data to be Appended...\n");
        }
        else
        {
          consPrefix("\n[*] ", consYel);
          printf("File Size MisMatch\n");
        }

        if (binLog == 1)
        { 
          if (fileIsFrag == 1)
            fprintf(LogHndl, "\n[*] File Size Fragmentation - More Data to be Appended...\n");
          else
            fprintf(LogHndl, "\n[*] File Size MisMatch\n");
        }
      }
      else
      {
        consPrefix("\n[+] ", consGre);
        printf("File Sizes Match\n");

        if (binLog == 1)
          fprintf(LogHndl, "[+] File Sizes Match\n");
      }

      fflush(stdout); //More PSExec Friendly

    }

    useDiskOrMem = maxMemExceed = 0; //Reset Default to Memory
    delete[] file;
    fflush(stdout); //More PSExec Friendly
    return 0;

  }

  useDiskOrMem = maxMemExceed = 0; //Reset Default to Memory
  delete[] file;
  fflush(stdout); //More PSExec Friendly
  return 0;

}

void consPrefix(char *consText, int consColor)
{
  SetConsoleTextAttribute(hConsole, consColor);
  printf("%s", consText);
  SetConsoleTextAttribute(hConsole, consWhi);
  fflush(stdout); //More PSExec Friendly
}


void getCaseInfo(int SayOrGet)
{
  // Say = 0, Get = 1
  if (SayOrGet == 1)
  {
    // Enter New Case Information
    if (iCase == 1)
    {
      // We ran this routine already once.
      // Avoid confusing multiple Case Names by running only once!
      consPrefix("\n[!] ", consRed);
      fprintf(LogHndl, "\n[!] Case Information Can Only Be Entered Once.\n");
      printf("Case Information Can Only Be Entered Once.\n");
    }
    else
    {
      consPrefix("\n[*] ", consBlu);
      fprintf(LogHndl, "\n[*] Default Case Number: %s\n", caseNumbr);
      printf("Default Case Number: %s\n", caseNumbr);
      consInput("Enter New Case Number (Or Enter To Accept Default): ", 1, 0);
      if(strlen(Conrec) > 0)
       strncpy(caseNumbr, Conrec, 251);

      consPrefix("\n[*] ", consBlu);
      fprintf(LogHndl, "\n[*] Default Case Description: %s\n", caseDescr);
      printf("Default Case Description: %s\n", caseDescr);
      consInput("Enter New Case Description (Or Enter to Accept Default: ", 1, 0);
      if(strlen(Conrec) > 0)
       strncpy(caseDescr, Conrec, 251);

      consPrefix("\n[*] ", consBlu);
      fprintf(LogHndl, "\n[*] Default Evidence Number: %s\n", evidNumbr);
      printf("Default Evidence Number: %s\n", evidNumbr);
      consInput("Enter New Evidence Number (Or Enter to Accept Default): ", 1, 0);
      if(strlen(Conrec) > 0)
       strncpy(evidNumbr, Conrec, 251);

      consPrefix("\n[*] ", consBlu);
      fprintf(LogHndl, "\n[*] Default Examiner: %s\n", caseExmnr);
      printf("Default Examiner: %s\n", caseExmnr);
      consInput("Enter New Examiner (Or Enter to Accept Default): ", 1, 0);
      if(strlen(Conrec) > 0)
       strncpy(caseExmnr, Conrec, 251);
    }

    fflush(stdout); //More PSExec Friendly

  }

  /****************************************************************/
  /* Display Case Information                                     */
  /****************************************************************/
  strtok(Inrec, "\n");
  strtok(Inrec, "\r");

  consPrefix("\n[*] ", consBlu);
  fprintf(LogHndl, "\n[*] Case Number: %s\n", caseNumbr);
  printf("Case Number: %s\n", caseNumbr);

  consPrefix("[*] ", consBlu);
  fprintf(LogHndl, "[*] Case Description: %s\n", caseDescr);
  printf("Case Description: %s\n", caseDescr);

  consPrefix("[*] ", consBlu);
  fprintf(LogHndl, "[*] Evidence Number: %s\n", evidNumbr);
  printf("Evidence Number: %s\n", evidNumbr);

  consPrefix("[*] ", consBlu);
  fprintf(LogHndl, "[*] Examiner: %s\n\n", caseExmnr);
  printf("Examiner: %s\n\n", caseExmnr);

  // Run This Routine ONLY ONCE to avoid ambiguity
  fflush(stdout); //More PSExec Friendly
  iCase = 1;
}


/************************************************************/
/* Get NTP Time                                             */
/* This code is  Mish-Mosh of code I grabbed from all over  */
/*  the Internet - Including much of David Lettier's        */
/*  NTP code at: github.com/lettier/ntpclient               */
/*                                                          */
/* +Copyright (c) 2014, David Lettier                       */
/* +All rights reserved.                                    */
/*                                                          */
/* Much of it was trial and error, but it works!            */
/************************************************************/
int ntpGetTime(char* ntpServer)
{
  int  ntpPort=123;  //NTP is port 123
  long ntpRC;
  int  ntpRecvRC = -1;
  int  i;

  typedef struct
  {
    uint8_t flags;           // Eight bits. Flags (li = 2, vn = 3, and mode = 3)

    uint8_t stratum;         // Eight bits. Stratum level of the local clock.
    uint8_t poll;            // Eight bits. Maximum interval between successive messages.
    uint8_t precision;       // Eight bits. Precision of the local clock.

    uint32_t rootDelay;      // 32 bits. Total round trip delay time.
    uint32_t rootDispersion; // 32 bits. Max error aloud from primary clock source.
    uint32_t refId;          // 32 bits. Reference clock identifier.

    uint32_t refTm_s;        // 32 bits. Reference time-stamp seconds.
    uint32_t refTm_f;        // 32 bits. Reference time-stamp fraction of a second.

    uint32_t origTm_s;       // 32 bits. Originate time-stamp seconds.
    uint32_t origTm_f;       // 32 bits. Originate time-stamp fraction of a second.

    uint32_t rxTm_s;         // 32 bits. Received time-stamp seconds.
    uint32_t rxTm_f;         // 32 bits. Received time-stamp fraction of a second.

    uint32_t txTm_s;         // 32 bits and the most important field the client cares about. Transmit time-stamp seconds.
    uint32_t txTm_f;         // 32 bits. Transmit time-stamp fraction of a second.

  } ntpPacket;              // Total: 384 bits or 48 bytes.

  ntpPacket ntpOut = {0, 0, 0, 0, 0, 0, 0, 0, 0};  // the packet we send

  char *ntpBuf = new char[1024];          // the buffer we get back

  struct sockaddr_in server_addr;
  struct hostent *ntpXServer;             // Server data structure.

  struct in_addr ntpIPaddr;
  SOCKET Sockit;
  struct tm *ntpLocal;
  int    ntpTimeVal = 1500;

  char WhatZone[255] ;
  TIME_ZONE_INFORMATION ltzinfo ;
  DWORD retval ; 


  //What is the Local Time Zone?
  retval = GetTimeZoneInformation( &ltzinfo ) ;


  //Parse Local Time Zone into WhatZone
  //Not Currently in Use - But may be in the future
  for(i=0;i<32;i++)
  {
    if(retval == TIME_ZONE_ID_STANDARD ) 
     WhatZone[i] = (char) ltzinfo.StandardName[i] ;
    else 
     WhatZone[i] = (char) ltzinfo.DaylightName[i];
  }

  //Start Winsock
  WSADATA wsaData;
  BYTE wsMajorVersion = 1;
  BYTE wsMinorVersion = 1;
  WORD wVersionRequested = MAKEWORD(wsMinorVersion, wsMajorVersion);   
 
  if (WSAStartup(wVersionRequested, &wsaData) != 0) 
  {
    consPrefix("\n[!] ", consRed);
    printf("NTP ERROR - Winsock could not startup.\n");

    if(iLogOpen == 1)
     fprintf(LogHndl, "[!] NTP ERROR - Winsock could not startup.\n");

    sprintf(ntpDateTime, "<Winsock Error>");
    WSACleanup();
    return(1);
  }

  if (LOBYTE(wsaData.wVersion) != wsMajorVersion || HIBYTE(wsaData.wVersion) != wsMinorVersion)
  {
    consPrefix("\n[!] ", consRed);
    printf("NTP ERROR - Winsock 1.1 is not supported.\n");

    if(iLogOpen == 1)
     fprintf(LogHndl, "[!] NTP ERROR - Winsock 1.1 is not supported.\n");

    sprintf(ntpDateTime, "<Winsock Error>");
    WSACleanup();
    return(2);
  }


  //Open a UDP Socket
  Sockit = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );

  if (Sockit < 0)
  {
    consPrefix("\n[!] ", consRed);
    printf( "NTP ERROR opening socket.\n" );

    if(iLogOpen == 1)
     fprintf(LogHndl, "[!] NTP ERROR opening socket.\n");

    sprintf(ntpDateTime, "<Winsock Error>");
    return(3);
  }

  //DNS Lookup to convert FQDN to IP
  ntpXServer = gethostbyname(ntpServer);

  if ( ntpXServer == NULL )
  {
    consPrefix("\n[!] ", consRed);
    printf( "NTP ERROR, no such host.\n" );

    if(iLogOpen == 1)
     fprintf(LogHndl, "[!] NTP ERROR, no such host..\n");

    sprintf(ntpDateTime, "<Unknown NTP Host>");
    return(4);
  }

  //Pick First IP Address in the List - It's easier
  ntpIPaddr.s_addr = *(u_long *) ntpXServer->h_addr_list[0];

  //printf("FQDN: %s\n", ntpServer);
  //printf("IPv4 Address: %s\n", inet_ntoa(ntpIPaddr));

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family=AF_INET;
  server_addr.sin_addr.s_addr = ntpIPaddr.s_addr;
  server_addr.sin_port=htons(ntpPort);


  /***********************************************************************/
  /* NTP Request Message - 48 Bytes in Length. Packet initialized to x00 */
  /*  except first byte: 00,011,011 for li = 0, vn = 3, and mode = 3     */
  /***********************************************************************/
  //printf("Sending...\n");
  memset(&ntpOut, 0, 48);
  *(( char *) &ntpOut + 0) = 0x1b;

  ntpRC = sendto(Sockit, (char *) &ntpOut, sizeof(ntpOut), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
  if(ntpRC == SOCKET_ERROR)
  {
    consPrefix("\n[!] ", consRed);
    printf("NTP Socket Error.\n");

    if(iLogOpen == 1)
     fprintf(LogHndl, "[!] NTP Socket Error.\n");

    sprintf(ntpDateTime, "<Winsock Error>");
    return(5);
  }
  //else
  // printf("Bytes Sent (Should be 48):%ld\n", ntpRC);


  //Set The Socket Timeout to 1/2 Second
  if (setsockopt(Sockit, SOL_SOCKET, SO_RCVTIMEO, (char*)&ntpTimeVal, sizeof(int)) < 0) 
  {
    consPrefix("\n[!] ", consRed);
    printf("NTP ERROR - Could not Set Socket TimeOut.\n");

    if(iLogOpen == 1)
     fprintf(LogHndl, "[!] NTP ERROR - Could not Set Socket TimeOut.\n");

    sprintf(ntpDateTime, "<Winsock Error>");
    return(6);
  }


  // Receive NTP data into buffer
  //printf("Receiving...\n");
  ntpRecvRC = -1;
  ntpRecvRC = recv(Sockit, (char *) &ntpOut, 1024, 0);


  if (ntpRecvRC > 0)
  {
    ntpOut.txTm_s = ntohl(ntpOut.txTm_s);   // Time-stamp seconds.
    ntpOut.txTm_f = ntohl(ntpOut.txTm_f);   // Time-stamp fraction of a second.

    time_t txTm = (time_t) (ntpOut.txTm_s - NTP_TIMESTAMP_DELTA );

    //Convert into a format I like
    ntpLocal = localtime((const time_t*) &txTm);
    sprintf(ntpDateTime, "%02d/%02d/%04d - %02d:%02d:%02d",
      ntpLocal->tm_mon + 1, ntpLocal->tm_mday, (ntpLocal->tm_year + 1900),
      ntpLocal->tm_hour, ntpLocal->tm_min, ntpLocal->tm_sec);
  }
  else
  if (ntpRecvRC == 0 )
  {
    //Connection Closed
    return(7);
  }
  else
  {
    //The NTP Query had some type of Error
    consPrefix("\n[!] ", consRed);
    printf("NTP Query Failed: %d\n", WSAGetLastError());

    if(iLogOpen == 1)
     fprintf(LogHndl, "NTP Query Failed: %d\n", WSAGetLastError());

    sprintf(ntpDateTime, "<NTP Failed>");
    return(8);
  }

  return(0);

}


static PUCHAR lznt1_decompress_chunk (UCHAR * dst, ULONG dst_size, UCHAR * src, ULONG src_size)
{
  UCHAR *src_cur, *src_end, *dst_cur, *dst_end;
  ULONG displacement_bits, length_bits;
  ULONG code_displacement, code_length;
  WORD flags, code;
  
  src_cur = src;
  src_end = src + src_size;
  dst_cur = dst;
  dst_end = dst + dst_size;
  
  /* Partial decompression is no error on Windows. */
  while (src_cur < src_end && dst_cur < dst_end)
  {
    /* read flags header */
    flags = 0x8000 | *src_cur++;

    /* parse following 8 entities, either uncompressed data or backwards reference */
    while ((flags & 0xFF00) && src_cur < src_end)
    {
      if (flags & 1)
      {
        /* backwards reference */
        if (src_cur + sizeof(WORD) > src_end)
         return NULL;

        code = *(WORD *)src_cur;
        src_cur += sizeof(WORD);
   
        /* find length / displacement bits */
        for (displacement_bits = 12; displacement_bits > 4; displacement_bits--)
         if ((1 << (displacement_bits - 1)) < dst_cur - dst) 
          break;

        length_bits       = 16 - displacement_bits;
        code_length       = (code & ((1 << length_bits) - 1)) + 3;
        code_displacement = (code >> length_bits) + 1;
 
        /* ensure reference is valid */
        if (dst_cur < dst + code_displacement)
         return NULL;
 
        /* copy bytes of chunk - we can't use memcpy()
        * since source and dest can be overlapping */
        while (code_length--)
        {
          if (dst_cur >= dst_end) 
           return dst_cur;

          *dst_cur = *(dst_cur - code_displacement);
          dst_cur++;
        }
      }
      else
      {
        /* uncompressed data */
        if (dst_cur >= dst_end)
         return dst_cur;

        *dst_cur++ = *src_cur++;
      }
      flags >>= 1;
    }
    
  }
  
  return dst_cur;
}


static NTSTATUS lznt1_decompress ( UCHAR * dst, ULONG dst_size, UCHAR * src, ULONG src_size, ULONG offset, ULONG * final_size, UCHAR * workspace)
{
  UCHAR *src_cur = src, *src_end = src + src_size;
  UCHAR *dst_cur = dst, *dst_end = dst + dst_size;
  ULONG chunk_size, block_size;
  WORD chunk_header;
  UCHAR *ptr;


  if (src_cur + sizeof(WORD) > src_end)
  {
    //Debug
    //printf ("Past src end 1 - Next Loc: %lu -- End: %lu \n", src_cur + sizeof(WORD), src_end);
    return STATUS_BAD_COMPRESSION_BUFFER;
  }
 

  /* skip over chunks which have a big distance (>= 0x1000) to the destination offset */
  while (offset >= 0x1000 && src_cur + sizeof(WORD) <= src_end)
  {
    /* read chunk header and extract size */
    chunk_header = *(WORD *)src_cur;
    src_cur += sizeof(WORD);
    //Debug
    //tot_byt_src += sizeof(WORD);

    if(!chunk_header)
    {
      //Debug
      //printf ("Not Chunk Header 1\n");
      goto out;
    }


    /* ensure we have enough buffer to process chunk */
    chunk_size = (chunk_header & 0xFFF) + 1;
    if (src_cur + chunk_size > src_end)
    {
      //Debug
      //printf ("Past src end 2\n");
      return STATUS_BAD_COMPRESSION_BUFFER;
    }


    //tot_byt_src += chunk_size;
    src_cur += chunk_size;
    offset  -= 0x1000;
  }

  
  /* this chunk is can be included partially */
  if (offset && src_cur + sizeof(WORD) <= src_end)
  {
    /* read chunk header and extract size */
    chunk_header = *(WORD *)src_cur;
    src_cur += sizeof(WORD);
    //tot_byt_src += sizeof(WORD);


    if (!chunk_header)
    {
      //Debug
      //printf ("Past src end 3\n");
      goto out;
    }


    /* ensure we have enough buffer to process chunk */
    chunk_size = (chunk_header & 0xFFF) + 1;
    if (src_cur + chunk_size > src_end)
    {
      //Debug
      //printf ("Past src end 4\n");
      return STATUS_BAD_COMPRESSION_BUFFER;
    }


    if (dst_cur >= dst_end)
     goto out;
  

    if (chunk_header & 0x8000)
    {
      /* compressed chunk */
      if (!workspace)
      {
        //Debug
        //printf ("Access Violation\n");
       return STATUS_ACCESS_VIOLATION;
      }


      ptr = lznt1_decompress_chunk(workspace, 0x1000, src_cur, chunk_size);
      if (!ptr) 
      {
        //Debug
        //printf ("Error Decompressing Chunk\n");
       return STATUS_BAD_COMPRESSION_BUFFER;
      }


      if (ptr - workspace > offset)
      {
        block_size = min ((ptr - workspace) - offset, dst_end - dst_cur);
        memcpy(dst_cur, workspace + offset, block_size);
        dst_cur += block_size;
      }
    }
    else
    {
      /* uncompressed chunk */
      if (chunk_size > offset)
      {
        block_size = min(chunk_size - offset, dst_end - dst_cur);
        memcpy(dst_cur, src_cur + offset, block_size);
        dst_cur += block_size;
      }
    }
    src_cur += chunk_size;
    //tot_byt_src += chunk_size;
  }

  
  /* handle remaining chunks */
  while (src_cur + sizeof(WORD) <= src_end)
  {
    /* read chunk header and extract size */
    chunk_header = *(WORD *)src_cur;
    src_cur += sizeof(WORD);
    //tot_byt_src += sizeof(WORD);

    if (!chunk_header) 
    {
      //Debug
      //printf ("Not Chunk Header(2)\n");
      goto out;
    }

    chunk_size = (chunk_header & 0xFFF) + 1;

    if (src_cur + chunk_size > src_end)
    {
      //Debug
      //printf ("Past src end 5\n");
      return STATUS_BAD_COMPRESSION_BUFFER;
    }
  
    /* add padding if required */
    block_size = ((dst_cur - dst) + offset) & 0xFFF;
    if (block_size)
    {
      block_size = 0x1000 - block_size;
      if (dst_cur + block_size >= dst_end)
      {
        //Debug
        //printf ("Past dst end\n");
        goto out;
      }

      memset(dst_cur, 0, block_size);
      dst_cur += block_size;
    }
 
    if (dst_cur >= dst_end)
    {
      //Debug
      //printf ("Past dst end\n");
      goto out;
    }

    if (chunk_header & 0x8000)
    {
      /* compressed chunk */
      //Debug
      //lst_cur = src_cur - src;
      //printf("Good: Cur in: %04x - Last offset: %04x\n", src_cur, lst_cur);
      dst_cur = lznt1_decompress_chunk(dst_cur, dst_end - dst_cur, src_cur, chunk_size);

      if (!dst_cur) 
      {
        //Debug
        //printf ("Error Decompressing Chunk\n");
        return STATUS_BAD_COMPRESSION_BUFFER;
      }
    }
    else
    {
      /* uncompressed chunk */
      block_size = min(chunk_size, dst_end - dst_cur);
      memcpy(dst_cur, src_cur, block_size);
      dst_cur += block_size;
    }

      src_cur += chunk_size;
      //tot_byt_src += chunk_size;
  }
   
out:
  if (final_size)
   *final_size = dst_cur - dst;
  
  return STATUS_SUCCESS;
  
}


BOOL CompareWindowsVersion(DWORD dwMajorVersion, DWORD dwMinorVersion)
{
    OSVERSIONINFOEX ver;
    DWORDLONG dwlConditionMask = 0;

    ZeroMemory(&ver, sizeof(OSVERSIONINFOEX));
    ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    ver.dwMajorVersion = dwMajorVersion;
    ver.dwMinorVersion = dwMinorVersion;

    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_EQUAL);

    return VerifyVersionInfo(&ver, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask);
}
