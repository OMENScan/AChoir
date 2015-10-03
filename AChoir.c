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
/*                                                              */
/*  rc=0 - All Good                                             */
/*  rc=1 - Bad Input                                            */
/*  rc=2 - Bad Execution                                        */
/*  rc=3 - Internal Error                                       */
/*                                                              */
/****************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/*#ifndef NO_UNISTD
#include <unistd.h>
#endif NO_UNISTD */

#include <conio.h>
#include <time.h>
#include <io.h>
#include <direct.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <process.h>
#include <windows.h>
#include "md5.h"

#include <Winnetwk.h>

#include <curl/curl.h>

#include <winbase.h>
#include <winnt.h>


#define NUL '\0'
#define MaxArray 100
#define BUFSIZE 4096
#define KEY_WOW64_64KEY 0x0100
#define KEY_WOW64_32KEY 0x0200

char Version[10] = "v0.28\0" ;
char RunMode[10] = "Run\0";
int  iRanMode = 0 ;
int  iRunMode = 0 ;
int  iHtmMode = 0 ;
int  iChkYN = 0 ;
int  iChkRC = 0 ;

char ACQName[255] ;
char ACQDir[1024] ;
char BACQDir[1024] ;

char buffer[BUFSIZE];
char filename[FILENAME_MAX] ;  

int verboseflag=0 ;
int DebugFlag=0 ;

void stripfilename(char *path) ;
int ListDir(char *DirName, char *LisType) ;
long Squish(char *SqString) ;
long twoSplit(char *SpString) ;
char *stristr(const char *String, const char *Pattern) ;
int  FileMD5(char *MD5FileName) ;
int  MemAllocErr(char *ErrType) ;
int  binCopy(char *FrmFile, char *TooFile) ;
void Time_tToFileTime(time_t InTimeT, int whichTime) ;
long varConvert(char *inVarRec) ;
long consInput(char *consString) ;
long mapsDrive(char *mapString) ;


FILE* LogHndl ;
FILE* CpyHndl ;
FILE* ForHndl ;
FILE* MD5Hndl ;
FILE* IniHndl ;
FILE* WGetHndl ;
FILE* HtmHndl ;

char LogFile[1024]  = "C:\\AChoir\\AChoir.exe\0" ;
char CpyFile[1024]  = "C:\\AChoir\\AChoir.exe\0" ;
char ChkFile[1024]  = "C:\\AChoir\\AChoir.exe\0" ;
char MD5File[1024]  = "C:\\AChoir\\Hashes.txt\0" ;
char ForFile[1024]  = "C:\\AChoir\\ForFiles\0" ;
char IniFile[1024]  = "C:\\AChoir\\AChoir.ACQ\0" ;
char HtmFile[1024]  = "C:\\AChoir\\Index.html\0" ;
char TempDir[1024]  = "C:\\AChoir\0" ;
char BaseDir[1024]  = "C:\\AChoir\0" ;
char CurrDir[1024]  = "\0" ;
char CurrFil[255]   = "AChoir.dat\0" ;
char DiskDrive[5]   = "C:\0\0\0" ;
char MapDrive[5]    = "C:\0\0\0" ;
char *WinRoot       = "C:\\Windows" ;
char *Procesr       = "AMD64" ;
char *TempVar       = "C:\\Windows\\Temp" ;
char *ProgVar       = "C:\\Program Files" ;

int  WGetIni, WGetIsGood, WGotIsGood ;

char WGetFile[1024] = "C:\\AChoir\\Achoir.dat\0" ;
char WGetURL[1024]  = "http://127.0.0.1/AChoir/AChoir.dat\0" ;

char FileRoot[1024] = "C:\\InetPub\\wwwroot\0" ;
char FullRoot[1024] = "C:\\InetPub\\wwwroot\0" ;

char LastRec[2048] ;
char ThisRec[2048] ;
char cpyChar ;

char FilArray[MaxArray][MaxArray] ;

int  iMonth, iDay, iYear, iHour, iMin, iSec, iYYYY ;
unsigned long LCurrTime ;

time_t timeval ;
struct tm *lclTime ;
char CDate[15] = "01/01/0001\0" ;
char CTime[15] = "01:01:00\0" ;

char MD5In1[256] = "\0" ;
char MD5In2[256] = "\0" ;
char MD5Out[256] = "\0" ;

int  iNeedSize ;
int  iLeftSize ;
char *recvData ;
char *recvTemp ;
int  recvSize = 25000 ;

int  LastRC = 0 ;
int  ChkRC = 0 ;
char *ExePtr, *ParmPtr, *CopyPtr;

size_t write_file(void *ptr, size_t size, size_t nmemb, FILE *stream) ;

char RootDir[FILENAME_MAX] = " \0" ;
char FullFName[FILENAME_MAX] ;  
char ForFName[FILENAME_MAX] ;  

DWORD netRC = NO_ERROR;
NETRESOURCE netRes = {0};
TCHAR szConnection[MAX_PATH];
DWORD ConnectSize = MAX_PATH, ConnectResult, Flags = (CONNECT_INTERACTIVE | CONNECT_REDIRECT);

int iPrm1, iPrm2, iPrm3 ;
char *iPtr1, *iPtr2, *iPtr3 ;

struct stat Frmstat ;
FILETIME TmpTime ;
FILETIME ToCTime ;
FILETIME ToMTime ;
FILETIME ToATime ;
LPFILETIME OutFileTime ;

LPCTSTR lpSubKey = TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\0");
DWORD ulOptions = 0;
REGSAM samWOW64   = KEY_READ | KEY_WOW64_64KEY ;
REGSAM samDesired = KEY_READ ;
long OpenK ;
long OpenRC ;

HKEY  hKey = HKEY_LOCAL_MACHINE;

HKEY   phkResult;
DWORD  dwIndex = 0 ;
TCHAR  lpValueName[2048] ;
DWORD  lpcchValueName = 2048 ;
LPTSTR lpData[2048] ;
DWORD  lpcbData = 2048 ;

int  samLoop = 0 ;
char o32VarRec[4096] ;
char o64VarRec[4096] ;
int  i64x32 ;

char Inrec[4096]  ;
char Inprec[255]  ;
char Conrec[255]  ;
char inUser[255]  ;
char inPass[255]  ;
char inMapp[255]  ;
char inFnam[255]  ;
int  iGoodMap = 0 ;
int  iArgsMap = 0 ;
int  getKey ;

int main(int argc, char *argv[])
{
  int i, j ;
  int iPtr, oPtr, ArnPtr ;
  int RunMe, ForMe, Looper, LoopNum ;

  char Tmprec[2048] ;
  char Filrec[2048] ;
  char Cpyrec[4096] ;
  char Exerec[4096] ;
  char Arnrec[2048] ;

  char *TokPtr, *Indx ;
  CURL *curl ;
  CURLcode res ;
  LCurrTime = time(NULL) ;
  char *ForSlash ;
  char *ForBlank ;

  char cName[MAX_COMPUTERNAME_LENGTH + 1] ;
  DWORD len = 55 ;

  time(&timeval) ;
  lclTime = localtime(&timeval) ;
  iMonth = lclTime->tm_mon+1 ;
  iDay   = lclTime->tm_mday ;
  iYYYY  = lclTime->tm_year+1900 ;
  iYear  = iYYYY - 2000 ;
  iHour  = lclTime->tm_hour ;
  iMin   = lclTime->tm_min ;
  iSec   = lclTime->tm_sec ;


  /****************************************************************/
  /* Set Defaults                                                 */
  /****************************************************************/
  memset(CurrDir, 0, 1024) ;
  memset(TempDir, 0, 1024) ;
  memset(BaseDir, 0, 1024) ;
  memset(BACQDir, 0, 1024) ;
  memset(Inprec, 0, 255) ;
  memset(Conrec, 0, 255) ;
  memset(inFnam, 0, 255) ;
  memset(inMapp, 0, 255) ;
  memset(inUser, 0, 255) ;
  memset(inPass, 0, 255) ;

  strncpy(inFnam, "AChoir.ACQ\0", 11) ;


  /****************************************************************/
  /* What Directory are we in?                                    */
  /****************************************************************/
  getcwd(BaseDir, 1000) ;


  /****************************************************************/
  /* Get Envars                                                   */
  /****************************************************************/
  WinRoot = getenv("systemroot")  ;
  Procesr = getenv("processor_architecture")  ;
  TempVar = getenv("temp")  ;
  ProgVar = getenv("programfiles")  ;


  /****************************************************************/
  /* Build the &ACQ Incident Number                               */
  /****************************************************************/
  if(GetComputerName(cName, &len) != 0)
   sprintf(ACQName, "ACQ-IR-%s-%04d%02d%02d-%02d%02d\0", cName, iYYYY, iMonth, iDay, iHour, iMin) ;
  else
   sprintf(ACQName, "ACQ-IR-%04d%02d%02d-%02d%02d\0", iYYYY, iMonth, iDay, iHour, iMin) ;


  /****************************************************************/
  /* Get the Runmode: (Default == 1)                              */
  /*  BLD = Go Get the Utilities via cURL                         */
  /*  MNU = Run the Menu.ACQ - a VERY simple menu script          */
  /*  RUN = Run the Live Acquisition Utility Script               */
  /*                                                              */
  /****************************************************************/
  iRunMode = 1 ;
  iArgsMap = 0 ;
  for(i=1; i<argc; i++)
  {
    if((strnicmp(argv[i], "/Help", 5) == 0) && (strlen(argv[i]) < 255))
    {
      printf("AChoir Arguments:\n\n") ;
      printf(" /HELP - This Description\n") ;
      printf(" /BLD  - Run the Build.ACQ Script (Build the AChoir Toolkit)\n") ;
      printf(" /MNU  - Run the Menu.ACQ Script (A Simple AChoir Menu)\n") ;
      printf(" /RUN  - Run the AChoir.ACQ Script to do a Live Acquisition\n") ;
      printf(" /DRV:<x:> - Set the &DRV parameter\n") ;
      printf(" /USR:<UserID> - User to Map to Remote Server\n") ;
      printf(" /PWD:<Password> - Password to Map to Remote Server\n") ;
      printf(" /MAP:<Server\\Share> - Map to a Remote Server\n") ;
      printf(" /INI:<File Name> - Run the <File Name> script instead of AChoir.ACQ\n") ;

      exit(0) ;
    }
    else
    if((strnicmp(argv[i], "/BLD", 4) == 0) && (strlen(argv[i]) == 4)) 
    {
      strncpy(RunMode, "Bld\0", 4) ;
      strncpy(inFnam, "Build.ACQ\0", 10) ;
      iRunMode = 0 ;
    }
    else
    if((strnicmp(argv[i], "/RUN", 4) == 0) && (strlen(argv[i]) == 4))
    {
      strncpy(RunMode, "Run\0", 4) ;
      strncpy(inFnam, "AChoir.ACQ\0", 11) ;
      iRunMode = 1 ;
    }
    else
    if((strnicmp(argv[i], "/MNU", 4) == 0) && (strlen(argv[i]) == 4)) 
    {
      strncpy(RunMode, "Mnu\0", 4) ;
      strncpy(inFnam, "Menu.ACQ\0", 10) ;
      iRunMode = 3 ;
    }
    else
    if(strnicmp(argv[i], "/DRV:", 4) == 0)
    {
      if((argv[i][6] == ':') && (strlen(argv[i]) == 7))
      {
        strncpy(DiskDrive, argv[i]+5, 2) ;
        printf("Set: Disk Drive Set: %s\n", DiskDrive) ;
      }
      else
       printf("Err: Invalid Disk Drive Setting: %s\n", argv[i]+5) ;

    }
    else
    if((strnicmp(argv[i], "/INI:", 5) == 0) && (strlen(argv[i]) > 10))
    {
      if(strlen(argv[i]) < 254)
      {
        strncpy(RunMode, "Ini\0", 4) ;
        strncpy(inFnam, argv[i]+5, 254) ;
        iRunMode = 2 ;
      }
      else
       printf("Err: /INI:  Too Long (Greater than 254 chars)\n") ;
    }
    else
    if(strnicmp(argv[i], "/MAP:", 5) == 0)
    {
      if(strlen(argv[i]) < 254)
      {
        iArgsMap = 1 ;
        memset(inMapp, 0, 255) ;
        strncpy(inMapp, argv[i]+5, 254) ;
      }
      else
       printf("Err: /MAP:  Too Long (Greater than 254 chars)\n") ;
    }
    else
    if(strnicmp(argv[i], "/USR:", 5) == 0)
    {
      if(strlen(argv[i]) < 254)
      {
        memset(inUser, 0, 255) ;
        strncpy(inUser, argv[i]+5, 254) ;
      }
      else
       printf("Err: /USR:  Too Long (Greater than 254 chars)\n") ;
    }
    else
    if(strnicmp(argv[i], "/PWD:", 5) == 0)
    {
      if(strlen(argv[i]) < 254)
      {
        memset(inPass, 0, 255) ;
        strncpy(inPass, argv[i]+5, 254) ;
      }
      else
       printf("Err: /PWD:  Too Long (Greater than 254 chars)\n") ;
    }
    else
    {
      printf("Err: Bad Argument: %s\n", argv[i]) ;
    }
  }


  /****************************************************************/
  /* Should we Map a Drive First?  If yes, set the BaseDir too.   */
  /****************************************************************/
  if(iArgsMap == 1)
  {
    mapsDrive(inMapp) ;
    strncpy(BaseDir, MapDrive, 4) ;
  }



  /****************************************************************/
  /* Set Initial File Names (BaseDir needs to be set 1st)         */
  /****************************************************************/
  sprintf(IniFile, "%s\\%s\0", BaseDir, inFnam) ;
  sprintf(WGetFile, "%s\\AChoir.Dat\0", BaseDir) ;
  sprintf(ForFile, "%s\\ForFiles\0", BaseDir) ;
  sprintf(ChkFile, "%s\\AChoir.exe\0", BaseDir) ;
  sprintf(BACQDir, "%s\\%s\0", BaseDir, ACQName) ;



  /****************************************************************/
  /* Create Log Dir if it aint there                              */
  /****************************************************************/
  sprintf(LogFile, "%s\\Logs\0", BaseDir) ;
  if(access(LogFile, 0) != 0)
   mkdir(LogFile) ;


  /****************************************************************/
  /* Logging!                                                     */
  /****************************************************************/
  sprintf(LogFile, "%s\\Logs\\ACQ-IR-%04d%02d%02d-%02d%02d.Log\0", BaseDir, iYYYY, iMonth, iDay, iHour, iMin) ;
  LogHndl = fopen(LogFile, "w") ;
  if(LogHndl == NULL)
  {
    printf("Err: Could not Open Log File.\n") ;
    exit(3) ;
  }


  printf("Inf: AChoir ver: %s, Mode: %s\n", Version, RunMode) ;
  printf("Inf: Directory Has Been Set To: %s\\%s\n", BaseDir, CurrDir) ;
  printf("Set: Input Script Set:\n     %s\n\n", IniFile) ;

  fprintf(LogHndl, "Inf: AChoir ver: %s, Mode: %s\n", Version, RunMode) ;
  fprintf(LogHndl, "Inf: Directory Has Been Set To: %s\\%s\n", BaseDir, CurrDir) ;
  fprintf(LogHndl, "Set: Input Script Set:\n     %s\n\n", IniFile) ;



  /****************************************************************/
  /* If iRunMode=1 Create the BACQDir - Base Acquisition Dir      */
  /****************************************************************/
  if(iRunMode == 1)
  {
    // Have we created the Base Acquisition Directory Yet?
    fprintf(LogHndl, "Set: Creating Base Acquisition Directory: %s\n", BACQDir) ;
    printf("Set: Creating Base Acquisition Directory: %s\n", BACQDir) ;

    if(access(BACQDir, 0) != 0)
    {
      mkdir(BACQDir) ;
      PreIndex() ;
    }
  }



  /****************************************************************/
  /* Open The Input Script File                                   */
  /****************************************************************/
  memset(Inrec, 0, 4096) ;
  memset(Tmprec, 0, 2048) ;

  IniHndl = fopen(IniFile, "r") ;

  if(IniHndl != NULL)
  {
    RunMe = 0 ;  // Conditional run Script default is yes

    while(fgets(Tmprec, 1000, IniHndl))
    {
      /****************************************************************/
      /* Conditional Execution                                        */
      /****************************************************************/
      if(RunMe > 0)
      {
        if(strnicmp(Tmprec, "32B:", 4) == 0)
         RunMe++ ;
        else
        if(strnicmp(Tmprec, "64B:", 4) == 0)
         RunMe++ ;
        else
        if(strnicmp(Tmprec, "CKY:", 4) == 0)
         RunMe++ ;
        else
        if(strnicmp(Tmprec, "CKN:", 4) == 0)
         RunMe++ ;
        else
        if(strnicmp(Tmprec, "RC=:", 4) == 0)
         RunMe++ ;
        else
        if(strnicmp(Tmprec, "RC!:", 4) == 0)
         RunMe++ ;
        else
        if(strnicmp(Tmprec, "RC>:", 4) == 0)
         RunMe++ ;
        else
        if(strnicmp(Tmprec, "RC<:", 4) == 0)
         RunMe++ ;
        else
        if(strnicmp(Tmprec, "END:", 4) == 0)
         RunMe-- ;
      }
      else
      {
        Looper = 1 ; 
        if(stristr(Tmprec, "&FOR") > 0)
        {
          ForMe = 1 ;
          memset(Filrec, 0, 2048) ;

          ForHndl = fopen(ForFile, "r") ;

          if(ForHndl == NULL)
          {
            fprintf(LogHndl, "Err: &FOR Directory has not been set.  Ignoring &FOR Loop...\n") ;
            printf("Err: &FOR Directory has not been set.  Ignoring &FOR Loop...\n") ;
            Looper = 0 ;
          }
        }
        else
         ForMe = 0 ;


        /****************************************************************/
        /* Loop (FOR:) until Looper = 1                                 */
        /****************************************************************/
        LoopNum = 0 ;
        while(Looper == 1)
        {
          if(ForMe == 0)
           Looper = 0 ;
          else
          {
            if(fgets(Filrec, 1000, ForHndl))
            { 
              Looper = 1 ; 
              LoopNum++  ;

              strtok(Filrec, "\n") ; 
              strtok(Filrec, "\r") ; 


              /****************************************************************/
              /* Get Just the File Name                                       */
              /****************************************************************/
              if((ForSlash = strrchr(Filrec, '\\')) != NULL)
              {
                if(strlen(ForSlash+1) > 1)
                 strncpy(ForFName, ForSlash+1, 250) ;
                else
                 strncpy(ForFName, "Unknown\0", 8) ;
              }
              else
               strncpy(ForFName, Filrec, 250) ;
            }
            else
             break;
          }



          /****************************************************************/
          /* Expand the record, replacing variables                       */
          /****************************************************************/
          Inrec[0] = '\0' ;
          oPtr = 0 ;


          /****************************************************************/
          /* Check for System (DOS/Win) Variables and Expand them         */
          /****************************************************************/
          varConvert(Tmprec) ;


          /****************************************************************/
          /* Now Further expand o32VarRec for Achoir unique variables     */
          /****************************************************************/
          for(iPtr=0; iPtr < 2000; iPtr++)
          {
            if(strnicmp(o32VarRec+iPtr, "&Dir", 4) ==0 )
            {
              if(strlen(CurrDir) > 0 )
               sprintf(Inrec+oPtr, "%s\\%s", BaseDir, CurrDir) ;
              else
               sprintf(Inrec+oPtr, "%s", BaseDir) ;

              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Fil", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s", CurrFil) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Inp", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s", Inprec) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Acq", 4) ==0 )
            {
              if(strlen(ACQDir) > 0 )
               sprintf(Inrec+oPtr, "%s\\%s", BACQDir, ACQDir) ;
              else
               sprintf(Inrec+oPtr, "%s", BACQDir) ;

              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Win", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s", WinRoot) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Tmp", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s", TempVar) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&For", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s", Filrec) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Num", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%d\0", LoopNum) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Fnm", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s\0", ForFName) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Rcd", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%d\0", LastRC) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Chk", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s\0", ChkFile) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Drv", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s\0", DiskDrive) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Map", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s\0", MapDrive) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            if(strnicmp(o32VarRec+iPtr, "&Prc", 4) ==0 )
            {
              sprintf(Inrec+oPtr, "%s\0", Procesr) ;
              oPtr = strlen(Inrec) ;
              iPtr+= 3 ;
            }
            else
            {
              Inrec[oPtr] = o32VarRec[iPtr] ;
              oPtr++ ;
              Inrec[oPtr] = '\0' ;
            }
          }


          /****************************************************************/
          /* Now execute the Actions                                      */
          /****************************************************************/
          if(Inrec[0] == '*') ;
          else
          if(strlen(Inrec) < 5) ;
          else
          if(strnicmp(Inrec, "Acq:", 4) == 0)
          {
            /****************************************************************/
            /* Create/Set ACQ Directory                                     */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            // Have we created the Base Acquisition Directory Yet?
            if(access(BACQDir, 0) != 0)
            {
              mkdir(BACQDir) ;
              PreIndex() ;
            }

            // Explicit Path
            if(Inrec[4] == '\\')
            {
              memset(ACQDir, 0, 1024) ;

              if(strlen(Inrec) > 5)
              {
                sprintf(ACQDir, "%s\0", Inrec+5) ;
                sprintf(TempDir, "%s\\%s\0", BACQDir, ACQDir) ;
              }
              else
               sprintf(TempDir, "%s\0", BACQDir) ;
            }
            else
            {
              if(strlen(Inrec) > 4)
              {
                strcat(ACQDir, "\\\0") ;
                strcat(ACQDir, Inrec+4) ;
                sprintf(TempDir, "%s\\%s\0", BACQDir, ACQDir) ;
              }
            }

            if(access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "Set: Creating Acquisition Sub-Directory: %s\n", ACQDir) ;
              printf("Set: Creating Acquisition Sub-Directory: %s\n", ACQDir) ;
              mkdir(TempDir) ;

              if(iHtmMode == 1)
              {
                fprintf(HtmHndl, "</td><td align=center>\n") ;
                fprintf(HtmHndl, "<a href=file:%s target=AFrame> %s </a>\n", ACQDir, ACQDir) ;
              }
            }

            fprintf(LogHndl, "Set: Acquisition Sub-Directory Has Been Set To: %s\n", ACQDir) ;
            printf("Set: Acquisition Sub-Directory Has Been Set To: %s\n", ACQDir) ;

          }
          else
          if(strnicmp(Inrec, "Dir:", 4) == 0)
          {
            /****************************************************************/
            /* Set Current Directory                                        */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            if(Inrec[4] == '\\')
            {
              memset(CurrDir, 0, 1024) ;

              if(strlen(Inrec) > 5)
              {
                strncpy(CurrDir, Inrec+5, 1000) ;
                sprintf(TempDir, "%s\\%s\0", BaseDir, CurrDir) ;
              }
              else
               sprintf(TempDir, "%s\0", BaseDir) ;
            }
            else
            {
              if(strlen(Inrec) > 4)
              {
                strcat(CurrDir, "\\\0") ;
                strcat(CurrDir, Inrec+4) ;
                sprintf(TempDir, "%s\\%s\0", BaseDir, CurrDir) ;
              }
            }


            if(access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "Set: Creating Directory: %s\n", CurrDir) ;
              printf("Set: Creating Directory: %s\n", CurrDir) ;
              mkdir(TempDir) ;
            }

            fprintf(LogHndl, "Set: Directory Has Been Set To: %s\n", CurrDir) ;
            printf("Set: Directory Has Been Set To: %s\n", CurrDir) ;

          }
          else
          if(strnicmp(Inrec, "Fil:", 4) == 0)
          {
            /****************************************************************/
            /* Set Current File                                             */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            memset(CurrFil, 0, 255) ;
            strncpy(CurrFil, Inrec+4, 250) ;

            sprintf(TempDir, "%s\\%s\0", BaseDir, CurrDir) ;
            if(access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "Set: Creating Directory: %s\n", CurrDir) ;
              printf("Set: Creating Directory: %s\n", CurrDir) ;
              mkdir(TempDir) ;
            }

            fprintf(LogHndl, "Set: File Has Been Set To: %s\n", CurrFil) ;
            printf("Set: File Has Been Set To: %s\n", CurrFil) ;

          }
          else
          if(strnicmp(Inrec, "Ini:", 4) == 0)
          {
            /****************************************************************/
            /* Close the Old INI File and use this new one                  */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            sprintf(IniFile, "%s\0", Inrec+4) ;
            if(access(IniFile, 0) != 0)
            {
              fprintf(LogHndl, "Err: Requested INI File Not Found: %s - Ignored.\n", Inrec+4) ;
              printf("Err: Requested INI File Not Found: %s - Ignored.\n", Inrec+4) ;
            }
            else
            {
              fprintf(LogHndl, "Inf: Switching to INI File: %s\n", Inrec+4) ;
              printf("Inf: Switching to INI File: %s\n", Inrec+4) ;

              fclose(IniHndl) ;
              IniHndl = fopen(IniFile, "r") ;

              if(IniHndl != NULL)
                RunMe = 0 ;  // Conditional run Script default is yes
              else
              {
                fprintf(LogHndl, "Err: Could Not Open INI File: %s - Exiting.\n", Inrec+4) ;
                printf("Err: Could Not Open INI File: %s - Exiting.\n", Inrec+4) ;
                exit(3) ;
              }
            }
          }
          else
          if(strnicmp(Inrec, "Inp:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            consInput(Inrec+4) ;
            strncpy(Inprec, Conrec, 254) ;
          }
          else
          if(strnicmp(Inrec, "CPY:", 4) == 0)
          {
            /****************************************************************/
            /* Binary Copy From => To                                       */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            Squish(Inrec) ;  

            memset(Cpyrec, 0, 4096) ;
            strncpy(Cpyrec, Inrec+4, 4092) ;
            twoSplit(Cpyrec) ;

            if(iPrm2 == 0)
            {
              fprintf(LogHndl, "Err: Copying Requires both a FROM and a TO File\n") ;
              printf("Err: Copying Requires both a FROM and a TO File\n") ;
            }
            else
            {
              fprintf(LogHndl, "\nCpy: %s\n     %s\n", Cpyrec+iPrm1, Cpyrec+iPrm2) ;
              printf("\nCpy: %s\n     %s\n", Cpyrec+iPrm1, Cpyrec+iPrm2) ;

              binCopy(Cpyrec+iPrm1, Cpyrec+iPrm2) ;
            }
          }
          else
          if(strnicmp(Inrec, "ARN:", 4) == 0)
          {
            /****************************************************************/
            /* Dump AutoRun Keys                                            */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            Squish(Inrec) ;  



            /****************************************************************/
            /* Run Registry Scan Twice - First Time Native, Second Time     */
            /*  - Disable Wow6432Node to get the Keys                       */
            /****************************************************************/
            for(samLoop=0; samLoop < 2; samLoop++)
            { 
              /****************************************************************/
              /* Dump AutoRun Keys                                            */
              /****************************************************************/
              if(samLoop == 0)
               OpenK = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, &phkResult);
              else
               OpenK = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samWOW64, &phkResult);

              if (OpenK == ERROR_SUCCESS)
              {
                for(dwIndex=0; dwIndex < 1000; dwIndex++)
                {
                  lpcchValueName = 2048 ;
                  lpcbData = 2048 ;
                  OpenRC = RegEnumValue(phkResult, dwIndex, lpValueName, &lpcchValueName, NULL, NULL, (LPBYTE)lpData, &lpcbData);
                  if (OpenRC == ERROR_SUCCESS)
                  {
                    /****************************************************************/
                    /* Parse out the .exe - Ignore quotes                           */
                    /****************************************************************/
                    memset(Arnrec, 0, 2048) ;
                    memset(Cpyrec, 0, 4096) ;


                    /****************************************************************/
                    /* Check for possibl caller program (rundll32, cmd, etc...)     */
                    /****************************************************************/
                    snprintf(Arnrec, 2047, "%s", lpData) ;
                    for(ArnPtr=0; ArnPtr < strlen(Arnrec); ArnPtr++)
                    {
                      if(strnicmp(Arnrec+ArnPtr, "rundll32", 8) == 0)
                       ArnPtr+=7 ;
                      else
                      if(strnicmp(Arnrec+ArnPtr, "rundll32.exe", 12) == 0)
                       ArnPtr+=11 ;
                      else
                      if(strnicmp(Arnrec+ArnPtr, "cmd /c", 6) == 0)
                       ArnPtr+=5 ;
                      else
                      if(strnicmp(Arnrec+ArnPtr, "cmd.exe /c", 10) == 0)
                       ArnPtr+=9 ;
                      else
                      if(Arnrec[ArnPtr] == ' ') ;
                      else
                      if(Arnrec[ArnPtr] == '"') ;
                      else
                       break;
                    }
                    iPtr1 = Arnrec+ArnPtr ;

                    /****************************************************************/
                    /* Check for .dll or .exe                                       */
                    /****************************************************************/
                    iPtr2 = stristr(Arnrec, ".dll") ;
                    if(iPtr2 > 0)
                     iPtr2[4] = '\0' ;
                    else
                    {
                      iPtr2 = stristr(Arnrec, ".exe") ;
                      if(iPtr2 > 0)
                       iPtr2[4] = '\0' ;
                    }

                    if((iPtr3 = strrchr(iPtr1, '\\')) != NULL)
                    {
                      if(strlen(iPtr3+1) > 1)
                       iPtr3++ ;
                      else
                       iPtr3 = iPtr1 ;
                    }
                    else
                     iPtr3 = iPtr1 ;


                    /****************************************************************/
                    /* If the program is there, Copy it                             */
                    /****************************************************************/
                    varConvert(iPtr1) ;

                    if(access(o32VarRec, 0) == 0)
                    {
                      sprintf(Cpyrec, "%s\\%s\\%s-%s\0", BACQDir, ACQDir, lpValueName, iPtr3) ;

                      fprintf(LogHndl, "\nArn: %s\n     %s\n", lpValueName, lpData) ;
                      printf("\nArn: %s\n     %s\n", lpValueName, lpData) ;

                      binCopy(o32VarRec, Cpyrec) ;
                    }
                    else
                    {
                      fprintf(LogHndl, "\nArn: Not Found - %s\n     %s\n", lpValueName, lpData) ;
                      printf("\nArn: Not Found - %s\n     %s\n", lpValueName, lpData) ;
                    }


                    /****************************************************************/
                    /* Check for 64bit versions (if set)                            */
                    /****************************************************************/
                    if(i64x32 == 1)
                    {
                      if(access(o64VarRec, 0) == 0)
                      {
                        sprintf(Cpyrec, "%s\\%s\\%s(64)-%s\0", BACQDir, ACQDir, lpValueName, iPtr3) ;

                        fprintf(LogHndl, "\nArn: (64bit)%s\n     %s\n", lpValueName, lpData) ;
                        printf("\nArn: (64bit)%s\n     %s\n", lpValueName, lpData) ;

                        binCopy(o64VarRec, Cpyrec) ;
                      }
                      else
                      {
                        fprintf(LogHndl, "\nArn: Not Found (64bit) - %s\n     %s\n", lpValueName, lpData) ;
                        printf("\nArn: Not Found (64bit) - %s\n     %s\n", lpValueName, lpData) ;
                      }
                    }
                  }
                  else
                  if(OpenRC == ERROR_NO_MORE_ITEMS)
                   break;
                  else
                   printf("Error: %d\n", OpenRC) ;
                }

                RegCloseKey(phkResult) ;
              }
              else if(OpenK == ERROR_FILE_NOT_FOUND)
               printf("Run Key Doesnt exist\n") ;
              else if(OpenK == ERROR_ACCESS_DENIED)
               printf("Run Key Access Denied\n") ;
              else
               printf("Registry Error: %d\n", OpenK) ;
            }
          }
          else
          if(strnicmp(Inrec, "RC=:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            ChkRC = atoi(Inrec+4) ;

            if(LastRC != ChkRC)
             RunMe++ ;
          }
          else
          if(strnicmp(Inrec, "RC!:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            ChkRC = atoi(Inrec+4) ;

            if(LastRC == ChkRC)
             RunMe++ ;
          }
          else
          if(strnicmp(Inrec, "RC<:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code < n                                   */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            ChkRC = atoi(Inrec+4) ;

            if(LastRC >= ChkRC)
             RunMe++ ;
          }
          else
          if(strnicmp(Inrec, "RC>:", 4) == 0)
          {
            /****************************************************************/
            /* Check Last Return Code = n                                   */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            ChkRC = atoi(Inrec+4) ;

            if(LastRC <= ChkRC)
             RunMe++ ;
          }
          else
          if(strnicmp(Inrec, "CKY:", 4) == 0)
          {
            /****************************************************************/
            /* Check for File - If not there, bump RunMe (Dont Run)         */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            memset(ChkFile, 0, 1024) ;
            strncpy(ChkFile, Inrec+4, 1000) ;

            if(access(ChkFile, 0) != 0)
             RunMe++ ;
          }
          else
          if(strnicmp(Inrec, "64B:", 4) == 0)
          {
            /****************************************************************/
            /* Only Run if we are 64 bit Architecture                       */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            if(strnicmp(Procesr, "AMD64", 5) != 0)
             RunMe++ ;
          }
          else
          if(strnicmp(Inrec, "32B:", 4) == 0)
          {
            /****************************************************************/
            /* Only Run if we are 32 bit Architecture                       */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            if(strnicmp(Procesr, "X86", 3) != 0)
             RunMe++ ;
          }
          else
          if(strnicmp(Inrec, "CKN:", 4) == 0)
          {
            /****************************************************************/
            /* Check for File - If not there, bump RunMe (Dont Run)         */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            memset(ChkFile, 0, 1024) ;
            strncpy(ChkFile, Inrec+4, 1000) ;

            if(access(ChkFile, 0) == 0)
             RunMe++ ;
          }
          else
          if(strnicmp(Inrec, "REQ:", 4) == 0)
          {
            /****************************************************************/
            /* This File is REQUIRED (Or exit with an Error)                */
            /****************************************************************/

            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            if(access(Inrec+4, 0) != 0)
            {
              fprintf(LogHndl, "Required File Not Found: %s - Exiting!\n", Inrec+4) ;
              printf("Required File Not Found: %s - Exiting!\n", Inrec+4) ;
              exit (3) ;
            }
            else
            {
              fprintf(LogHndl, "Required File Found: %s\n", Inrec+4) ;
              printf("Required File Found: %s\n", Inrec+4) ;
            }
          }
          else
          if(strnicmp(Inrec, "SAY:", 4) == 0)
          {
            // Echo To Screen

            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            fprintf(LogHndl, "%s\n", Inrec+4) ;
            printf("%s\n", Inrec+4) ;
          }
          else
          if(strnicmp(Inrec, "PZZ:", 4) == 0)
          {
            /****************************************************************/
            /* Echo and Pause                                               */
            /****************************************************************/

            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            fprintf(LogHndl, "%s\n", Inrec+4) ;
            printf("%s\n", Inrec+4) ;
            getKey = getche() ;

            if((getKey == 81) || (getKey == 113))
            {
              fprintf(LogHndl, "\nYou have requested Achoir to Quit.\n") ;
              printf("\nYou have requested Achoir to Quit.\n") ;
              exit(0) ;
            }
          }
          else
          if(strnicmp(Inrec, "HSH:ACQ", 7) == 0)
          {
            /****************************************************************/
            /* Hash The Acquisition Directory                               */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            fprintf(LogHndl, "Inf: Now Hashing Acquisition Files\n") ;
            printf("Inf: Now Hashing Acquisition Files\n") ;
            sprintf(MD5File, "%s\\ACQHash.txt\0", BACQDir) ;
            sprintf(TempDir, "%s\\*.*\0", BACQDir) ;

            MD5Hndl = fopen(MD5File, "w") ;

            if(MD5Hndl != NULL)
            {
              ListDir(TempDir, "MD5") ;

              fclose(MD5Hndl) ;
            }
          }
          else
          if(strnicmp(Inrec, "HSH:Dir", 7) == 0)
          {
            /****************************************************************/
            /* Hash The Acquisition Directory                               */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            fprintf(LogHndl, "Inf: Now Hashing AChoir Files\n") ;
            printf("Inf: Now Hashing AChoir Files\n") ;
            sprintf(MD5File, "%s\\DirHash.txt\0", BaseDir) ;
            sprintf(TempDir, "%s\\*.*\0", BaseDir) ;

            MD5Hndl = fopen(MD5File, "w") ;

            if(MD5Hndl != NULL)
            {
              ListDir(TempDir, "MD5") ;

              fclose(MD5Hndl) ;
            }
          }
          else
          if(strnicmp(Inrec, "FOR:", 4) == 0)
          {
            /****************************************************************/
            /* Get the Directory Listing for the &For variable (Loop)       */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            sprintf(MD5File, "%s\\ForFiles\0", BaseDir) ;

            MD5Hndl = fopen(MD5File, "w") ;

            if(MD5Hndl != NULL)
            {
              ListDir(Inrec+4, "FOR") ;
              fclose(MD5Hndl) ;
            }
          }
          else
          if(strnicmp(Inrec, "END:", 4) == 0)
          {
            /****************************************************************/
            /* Decrement Conditional Pointer                                */
            /****************************************************************/
            if(RunMe > 0)
             RunMe-- ;
          }
          else
          if(strnicmp(Inrec, "BYE:", 4) == 0)
          {
            /****************************************************************/
            /* Exit the Script With LastRC (Probably Conditional)           */
            /****************************************************************/
            fprintf(LogHndl, "BYE: Exiting with RC = %d\n", LastRC) ;
            printf("BYE: Exiting with RC = %d\n", LastRC) ;

            if(access(ForFile, 0) == 0)
             unlink(ForFile) ;

            fclose(LogHndl) ;

            exit (LastRC) ;
          }
          else
          if(strnicmp(Inrec, "USR:", 4) == 0)
          {
            /****************************************************************/
            /* Map to an External Drive & Set it to ACQ Directory           */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            memset(inUser, 0, 255) ;
            strncpy(inUser, Inrec+4, 254) ;
          }
          else
          if(strnicmp(Inrec, "PWD:", 4) == 0)
          {
            /****************************************************************/
            /* Map to an External Drive & Set it to ACQ Directory           */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            memset(inPass, 0, 255) ;
            strncpy(inPass, Inrec+4, 254) ;
          }
          else
          if(strnicmp(Inrec, "MAP:", 4) == 0)
          {
            /****************************************************************/
            /* Map to an External Drive & Set it to ACQ Directory           */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            mapsDrive(Inrec+4) ;
          }
          else
          if(strnicmp(Inrec, "SYS:", 4) == 0)
          {
            /****************************************************************/
            /* Run a system (Shell) command                                 */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 


            // Are we requesting an explicit path?
            if(Inrec[4] == '\\')
            {
              memset(TempDir, 0, 1024) ;
              sprintf(TempDir, "%s%s\0", BaseDir, Inrec+4) ;
            }
            else
            {
              memset(TempDir, 0, 1024) ;
              sprintf(TempDir, "%s\0",Inrec+4) ;
            }


            fprintf(LogHndl, "\nSys: %s\n", TempDir) ;
            printf("\nSys: %s\n", TempDir) ;

            LastRC = system(TempDir) ;
            fprintf(LogHndl, "Return Code: %d\n", LastRC) ;
          }
          else
          if(strnicmp(Inrec, "EXE:", 4) == 0)
          {
            /****************************************************************/
            /* Spawn an Executable                                          */
            /****************************************************************/
            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            Squish(Inrec) ;  
            memset(Exerec, 0, 4096) ;
            strncpy(Exerec, Inrec+4, 4092) ;
            twoSplit(Exerec) ;


            // Are we requesting an explicit path?
            if(Exerec[0] == '\\')
            {
              memset(TempDir, 0, 1024) ;
              sprintf(TempDir, "%s%s\0", BaseDir, Exerec+iPrm1) ;
            }
            else
            {
              memset(TempDir, 0, 1024) ;
              sprintf(TempDir, "%s\0", Exerec+iPrm1) ;
            }



            /****************************************************************/
            /* Are There Any Parms?                                         */
            /****************************************************************/
            if(access(TempDir, 0) != 0)
            {
              fprintf(LogHndl, "Err: Program Not Found\n") ;
              printf("Err: Program Not Found\n") ;
            }
            else
            {
              FileMD5(TempDir) ;

              if(iPrm3 > 0)
              {
                fprintf(LogHndl, "\nExe: %s\n   : %s\n   : %s\n", Exerec+iPrm1, Exerec+iPrm2, Exerec+iPrm3) ;
                printf("\nExe: %s\n   : %s\n   : %s\n", Exerec+iPrm1, Exerec+iPrm2, Exerec+iPrm3) ;
                fprintf(LogHndl, "Inf: Program Hash: %s\n", MD5Out) ;
                printf("Inf: Program Hash: %s\n", MD5Out) ;

                LastRC = spawnlp(P_WAIT, TempDir, TempDir, Exerec+iPrm2, Exerec+iPrm3, NULL);
              }
              else
              if(iPrm2 > 0)
              {
                fprintf(LogHndl, "\nExe: %s\n   : %s\n", Exerec+iPrm1, Exerec+iPrm2) ;
                printf("\nExe: %s\n   : %s\n", Exerec+iPrm1, Exerec+iPrm2) ;
                fprintf(LogHndl, "Inf: Program Hash: %s\n", MD5Out) ;
                printf("Inf: Program Hash: %s\n", MD5Out) ;

                LastRC = spawnlp(P_WAIT, TempDir, TempDir, Exerec+iPrm2, NULL);
              }
              else
              {
                fprintf(LogHndl, "\nExe: %s\n", Exerec+iPrm1) ;
                printf("\nExe: %s\n", Exerec+iPrm1) ;
                fprintf(LogHndl, "Inf: Program Hash: %s\n", MD5Out) ;
                printf("Inf: Program Hash: %s\n", MD5Out) ;

                LastRC = spawnlp(P_WAIT, TempDir, TempDir, NULL);
              }


              if(LastRC != 0)
              {
                fprintf(LogHndl, "Spawn Error(%d): %s\n", errno, strerror(errno)) ;
                printf("Spawn Error(%d): %s\n", errno, strerror(errno)) ;
              }

              fprintf(LogHndl, "Return Code: %d\n", LastRC) ;
            }
          }
          else
          if(strnicmp(Inrec, "Get:", 4) == 0)
          {
            /****************************************************************/
            /* Use HTTP to GET a file                                       */
            /****************************************************************/
            // Ensure we are not in Run Only Mode (Mode:1)

            strtok(Inrec, "\n") ; 
            strtok(Inrec, "\r") ; 

            sprintf(WGetFile, "%s\\%s\0", CurrDir, CurrFil) ;
            fprintf(LogHndl, "Inf: Getting: %s\n", WGetFile) ;
            printf("Inf: Getting: %s\n", WGetFile) ;

           unlink(WGetFile) ;
            WGetHndl = fopen(WGetFile,"wb");

            if(WGetHndl != NULL)
            {
              curl = curl_easy_init();
              if(curl)
              {
                strncpy(WGetURL, Inrec+4, 1000) ;

                // curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                // curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

                curl_easy_setopt(curl, CURLOPT_URL, WGetURL);
                curl_easy_setopt(curl, CURLOPT_NOPROGRESS  ,1);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_file);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, WGetHndl);

                res = curl_easy_perform(curl);
                LastRC = res ;


                if(res != CURLE_OK)
                {
                  fprintf(LogHndl, "\nErr: Error (rc=%d) Downloading:\n     %s\n\n", res, Inrec+4) ;
                  printf("\nErr: Error (rc=%d) Downloading:\n     %s\n\n", res, Inrec+4) ;
                }
              }

              curl_easy_cleanup(curl);

              fclose(WGetHndl) ;

            }
            else
            {
              fprintf(LogHndl, "\nErr: Error Writing File:\n     %s\n\n", WGetFile) ;
              printf("\nErr: Error Writing File:\n     %s\n\n", WGetFile) ;
            }
          }
          /****************************************************************/
          /* End Of Script Processing Code                                */
          /****************************************************************/

        }

        if((ForMe == 1) && (ForHndl != NULL))
         fclose(ForHndl) ;

      }

    }

    fclose(IniHndl) ;

  }
  else
  {
    fprintf(LogHndl, "\nErr: Input Script Not Found:\n     %s\n\n", IniFile) ;
    printf("\nErr: Input Script Not Found:\n     %s\n\n", IniFile) ;
    exit (1) ;
  }



  /****************************************************************/
  /* Cleanup                                                      */
  /****************************************************************/
  if(RunMe > 0)
  {
    fprintf(LogHndl, "Err: You have and extra END: Hanging! Check your Logic.\n") ;
    printf("Err: You have and extra END: Hanging! Check your Logic.\n") ;
  }

  if(access(ForFile, 0) == 0)
   unlink(ForFile) ;


  if(iHtmMode == 1)
  {
    fprintf(HtmHndl, "</td><td align=right>\n");
    fprintf(HtmHndl, "<button onclick=\"window.history.forward()\">&gt;&gt;</button>\n");
    fprintf(HtmHndl, "</td></tr></table>\n<p>\n");
    fprintf(HtmHndl, "<iframe name=AFrame height=400 width=900 scrolling=auto src=file:./></iframe>\n");
    fprintf(HtmHndl, "</p>\n</body></html>\n");

    fclose(HtmHndl) ;
  }


  if(iRunMode == 1)
  {
    fprintf(LogHndl, "Inf: Setting All Artifacts to Read-Only.\n") ;
    printf("Inf: Setting All Artifacts to Read-Only.\n") ;

    sprintf(TempDir, "%s\\*.*\0", BACQDir) ;
    ListDir(TempDir, "ROS") ;
  }

  fclose(LogHndl) ;

  /****************************************************************/
  /* Make a Copy of the Logfile in the ACQDirectory               */
  /****************************************************************/
  if(access(BACQDir, 0) == 0)
  {
    fprintf(LogHndl, "Inf: Copying Log File...\n") ;
    printf("Inf: Copying Log File...\n") ;
    sprintf(CpyFile, "%s\\ACQ-IR-%04d%02d%02d-%02d%02d.Log\0", BACQDir, iYYYY, iMonth, iDay, iHour, iMin) ;
    binCopy(LogFile, CpyFile) ; 
  }

  exit (0) ;
  return 0 ;

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
    } else {
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
    SET(a, b, c, d,  0,  7,  T1);
    SET(d, a, b, c,  1, 12,  T2);
    SET(c, d, a, b,  2, 17,  T3);
    SET(b, c, d, a,  3, 22,  T4);
    SET(a, b, c, d,  4,  7,  T5);
    SET(d, a, b, c,  5, 12,  T6);
    SET(c, d, a, b,  6, 17,  T7);
    SET(b, c, d, a,  7, 22,  T8);
    SET(a, b, c, d,  8,  7,  T9);
    SET(d, a, b, c,  9, 12, T10);
    SET(c, d, a, b, 10, 17, T11);
    SET(b, c, d, a, 11, 22, T12);
    SET(a, b, c, d, 12,  7, T13);
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
    SET(a, b, c, d,  1,  5, T17);
    SET(d, a, b, c,  6,  9, T18);
    SET(c, d, a, b, 11, 14, T19);
    SET(b, c, d, a,  0, 20, T20);
    SET(a, b, c, d,  5,  5, T21);
    SET(d, a, b, c, 10,  9, T22);
    SET(c, d, a, b, 15, 14, T23);
    SET(b, c, d, a,  4, 20, T24);
    SET(a, b, c, d,  9,  5, T25);
    SET(d, a, b, c, 14,  9, T26);
    SET(c, d, a, b,  3, 14, T27);
    SET(b, c, d, a,  8, 20, T28);
    SET(a, b, c, d, 13,  5, T29);
    SET(d, a, b, c,  2,  9, T30);
    SET(c, d, a, b,  7, 14, T31);
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
    SET(a, b, c, d,  5,  4, T33);
    SET(d, a, b, c,  8, 11, T34);
    SET(c, d, a, b, 11, 16, T35);
    SET(b, c, d, a, 14, 23, T36);
    SET(a, b, c, d,  1,  4, T37);
    SET(d, a, b, c,  4, 11, T38);
    SET(c, d, a, b,  7, 16, T39);
    SET(b, c, d, a, 10, 23, T40);
    SET(a, b, c, d, 13,  4, T41);
    SET(d, a, b, c,  0, 11, T42);
    SET(c, d, a, b,  3, 16, T43);
    SET(b, c, d, a,  6, 23, T44);
    SET(a, b, c, d,  9,  4, T45);
    SET(d, a, b, c, 12, 11, T46);
    SET(c, d, a, b, 15, 16, T47);
    SET(b, c, d, a,  2, 23, T48);
#undef SET

     /* Round 4. */
     /* Let [abcd k s t] denote the operation
          a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + I(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
     /* Do the following 16 operations. */
    SET(a, b, c, d,  0,  6, T49);
    SET(d, a, b, c,  7, 10, T50);
    SET(c, d, a, b, 14, 15, T51);
    SET(b, c, d, a,  5, 21, T52);
    SET(a, b, c, d, 12,  6, T53);
    SET(d, a, b, c,  3, 10, T54);
    SET(c, d, a, b, 10, 15, T55);
    SET(b, c, d, a,  1, 21, T56);
    SET(a, b, c, d,  8,  6, T57);
    SET(d, a, b, c, 15, 10, T58);
    SET(c, d, a, b,  6, 15, T59);
    SET(b, c, d, a, 13, 21, T60);
    SET(a, b, c, d,  4,  6, T61);
    SET(d, a, b, c, 11, 10, T62);
    SET(c, d, a, b,  2, 15, T63);
    SET(b, c, d, a,  9, 21, T64);
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
  char buffer[1024*16];

  MD5Hndl = fopen(MD5FileName,"rb");

  if (MD5Hndl == NULL)
   return 0;

  cbRead = fread(buffer, 1, sizeof(buffer), MD5Hndl);

  md5_init(&state);

  while (cbRead > 0) 
  {
    md5_append(&state, (const md5_byte_t *)buffer, cbRead);

    cbRead = fread(buffer, 1, sizeof(buffer), MD5Hndl);
  }

  md5_finish(&state, digest);

  for (di = 0; di < 16; ++di) 
   sprintf(MD5Out+(di*2), "%02x", digest[di]) ;

  // printf("\nFile: %s, MD5:%s\n", MD5FileName, MD5Out) ;

  fclose(MD5Hndl) ;
  return 1;
}



/****************************************************************/
/* CURL Routine to write the URL output to a file               */
/****************************************************************/
size_t write_file(void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
  size_t written;

  written = fwrite(ptr, size, nmemb, stream);

  return written;
}



/***********************************************************/
/* Memory Allocation Problem                               */
/***********************************************************/
int MemAllocErr(char *ErrType)
{
  fprintf(LogHndl, "Err: Error Allocating Enough Memory For: %s\n\n", ErrType) ;
  printf("Err: Error Allocating Enough Memory For: %s\n\n", ErrType) ;

  // if(LogStart == 1)
  //  fprintf(OutHndl, "\nERROR-35: Error Allocating Enough Memory For: %s\n", ErrType) ;

  exit (3) ;
  return 2 ;
}



/****************************************************************/
/* Squish a String to delete non-alphanumrics                   */
/****************************************************************/
long Squish(char *SqString)
{
  long Sqi, SqLen ;

  //Zap any non-printable ending characters...
  for(Sqi=strlen(SqString); Sqi >= 0; Sqi--)
  {
    if((SqString[Sqi] < 33) || (SqString[Sqi] > 126))
      SqString[Sqi] = '\0' ;
    else
      break ;
  }

  SqLen = strlen(SqString) ;
  return SqLen ;
}



/****************************************************************/
/* convert a record with Environment Variables in it            */
/*  - Do manual checks for 64 bit exceptions - Check both 32&64 */
/****************************************************************/
long varConvert(char *inVarRec)
{
  int  inProgress, GVNi ;
  long Vari, Var32o, Var64o, VarLen ;
  char envVarName[255] = "Temp" ;
  char *convVar = "C:\\Temp" ;
  
  i64x32 = 0 ;
  Var32o = Var64o = GVNi = 0 ;
  inProgress = 0 ;
  memset(o32VarRec, 0, 4096) ;
  memset(o64VarRec, 0, 4096) ;
  memset(envVarName, 0, 255) ;

  VarLen = strlen(inVarRec) ;
  if(VarLen > 4095)
   VarLen = 4095 ;

  for(Vari=0; Vari < VarLen; Vari++)
  {
    if((inVarRec[Vari] == '%') && (inProgress == 0))
    {
      /****************************************************************/
      /* To prevent expansion use %%                                  */
      /****************************************************************/
      if(inVarRec[Vari+1] == '%')
      {
        o32VarRec[Var32o] = inVarRec[Vari] ;
        o64VarRec[Var64o] = inVarRec[Vari] ;
        Vari++ ;
        Var32o++ ; 
        Var64o++ ; 
      }
      else
       inProgress = 1 ;
    }
    else
    if((inVarRec[Vari] == '%') && (inProgress == 1))
    {
      inProgress = 0 ;
      convVar = getenv(envVarName)  ;


      /****************************************************************/
      /* Check for 32bit and 64bit differences                        */
      /****************************************************************/
      if(convVar == NULL) ;
      else
      if(strnicmp(convVar, "C:\\Program Files", 16) == 0)
      {
        i64x32 = 1 ;
        strcat(o32VarRec, "C:\\Program Files\0") ;
        strcat(o64VarRec, "C:\\Program Files (x86)\0") ;
      }
      else
      {
        strcat(o32VarRec, convVar) ;
        strcat(o64VarRec, convVar) ;
      }

      Var32o = strlen(o32VarRec) ;
      Var64o = strlen(o64VarRec) ;

      GVNi = 0 ;
      memset(envVarName, 0, 255) ;
    }
    else
    if(inProgress == 1)
    {
      envVarName[GVNi] = inVarRec[Vari] ;
      GVNi++ ;

      if(GVNi > 254)
       return 1 ;
    }
    else
    if(strnicmp(inVarRec+Vari, "System32", 8) == 0)
    {
      /****************************************************************/
      /* Check for System32 - (Do Checks for sysnative)               */
      /****************************************************************/
      i64x32 = 1 ;
      Vari+= 7 ;

      strcat(o32VarRec, "System32\0") ;
      strcat(o64VarRec, "sysnative\0") ;

      Var32o = strlen(o32VarRec) ;
      Var64o = strlen(o64VarRec) ;
    }
    else
    {
      o32VarRec[Var32o] = inVarRec[Vari] ;
      o64VarRec[Var64o] = inVarRec[Vari] ;
      Var32o++ ; 
      Var64o++ ; 
    }
  }

  return 0 ;
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
  long Spi, SpLen ;
  int  iParm, iSplt ;


  iParm = iSplt = 0 ;
  iPrm1 = iPrm2 = iPrm3 = 0 ;
  SpLen = strlen(SpString) ;

  for(Spi=0; Spi < SpLen; Spi++)
  {
    if((SpString[Spi] == ' ') && (iSplt == 0))
    {
      //Split - No Pending Quote (Only if there isnt a repeating blank

      if((SpString[Spi+1] == ' ') && (iParm == 0)) ;
      else
      if((SpString[Spi+1] == ' ') && (iParm == 1)) ;
      else
      {
        //Set to Parameter 1, 2, 3, etc...
        iParm++ ; 
       
        //For Parms greater than 1 - Ignore Split.
        if(iParm == 1)
        {      
          SpString[Spi] = '\0' ;
          iPrm2 = Spi+1 ;
        }
        else
        if(iParm == 2)
        {      
          SpString[Spi] = '\0' ;
          iPrm3 = Spi+1 ;
        }
      }
    }
    else
    if((SpString[Spi] == '"') && (iSplt == 0))
    {
      iSplt = 1 ;

      if(iParm == 0)
       iPrm1 = Spi+1 ;
      else
      if(iParm == 1)
       iPrm2 = Spi+1 ;
      else
      if(iParm == 2)
       iPrm3 = Spi ;
    }
    else
    if((SpString[Spi] == '"') && (iSplt == 1))
    {
      iSplt = 0 ;

      if(iParm < 2)
       SpString[Spi] = '\0' ;
    }
  }
  return iParm ;
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
    for ( ; ((*start!=NUL) && (toupper(*start) != toupper(*Pattern))); start++) ;
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
  struct _finddata_t ffblk   ;
  long DirDone               ;

  char inName[FILENAME_MAX] = " \0" ;
  char subDir[FILENAME_MAX] = " \0" ;

  char SrchDName[FILENAME_MAX] = "C:\\AChoir\0" ;
  char SrchFName[FILENAME_MAX] = "*.*\0" ;

  char *Slash ;
  char *TokPtr ;

  int iLisType, iCount ;



  /****************************************************************/
  /* What type of Directory Listing                               */
  /****************************************************************/
  if(strnicmp(LisType, "MD5", 3) == 0)
   iLisType = 1 ; 
  else
  if(strnicmp(LisType, "FOR", 3) == 0)
   iLisType = 2 ; 
  else
  if(strnicmp(LisType, "ROS", 3) == 0)
   iLisType = 3 ; 
  else
   iLisType = 2 ; 



  /****************************************************************/
  /* Loop throught the directory looking for those files.         */
  /*   Count up the tracks, mixes, and total bytecount            */
  /****************************************************************/
  strcpy(RootDir, DirName) ;

  if(iLisType == 1)
   fprintf(MD5Hndl, "Directory: %s\n", RootDir) ;



  /****************************************************************/
  /* Get rid of the SubDir info                                   */
  /****************************************************************/
  if((Slash = strrchr(RootDir, '\\')) != NULL)
  {
    if(strlen(Slash+1) > 1)
     strncpy(SrchFName, Slash+1, 250) ;
    else
     strncpy(SrchFName, "*.*\0", 4) ;
    
    strncpy(Slash, "\\\0", 2) ;
  }



  /****************************************************************/
  /* Search Twice.                                                */
  /*  First Search ALL to parse the directories                   */
  /*  Second Search for just File Names                           */
  /****************************************************************/
  sprintf(SrchDName, "%s*.*\0", RootDir) ;



  /****************************************************************/
  /* First Search - Loop through Subdirectories                   */
  /****************************************************************/
  if((DirDone = _findfirst(SrchDName, &ffblk)) != -1L)
  {
    do
    {
      if(ffblk.name[0] == '.')
        continue;


      /****************************************************************/
      /* Where are we?                                                */
      /****************************************************************/
      memset(inName, 0, FILENAME_MAX) ;
      strcpy(inName, ffblk.name)   ;


      /****************************************************************/
      /* SubDirectory Search                                          */
      /****************************************************************/
      if(ffblk.attrib & _A_SUBDIR) 
      {
        strcat(RootDir, inName) ;

        sprintf(subDir, "%s\\%s\0", RootDir, SrchFName) ;
        ListDir(subDir, LisType) ;

        /****************************************************************/
        /* Return to ..                                                 */
        /****************************************************************/
        strcpy(RootDir, DirName) ;

        if((Slash = strrchr(RootDir, '\\')) != NULL) 
         strncpy(Slash, "\\\0", 2) ;
      }

    } while (_findnext(DirDone, &ffblk) == 0);

    _findclose(DirDone) ;

  }


  /****************************************************************/
  /* Second Search for just File Names                            */
  /****************************************************************/
  if((DirDone = _findfirst(DirName, &ffblk)) != -1L)
  {
    do
    {
      if(ffblk.name[0] == '.')
        continue;


      /****************************************************************/
      /* Where are we?                                                */
      /****************************************************************/
      memset(inName, 0, FILENAME_MAX) ;
      strcpy(inName, ffblk.name)   ;


      /****************************************************************/
      /* Ignore SubDirectory Search - We Already Did This             */
      /****************************************************************/
      if(ffblk.attrib & _A_SUBDIR) ;
      else
      {
        sprintf(FullFName, "%s%s\0", RootDir, inName) ;

        if(iLisType == 1)
        {
          FileMD5(FullFName) ;
          fprintf(MD5Hndl,"File: %s - MD5: %s\n", FullFName, MD5Out) ;
        }
        else
        if(iLisType == 2)
         fprintf(MD5Hndl,"%s\n", FullFName) ;
        else
        if(iLisType == 3)
         SetFileAttributes(FullFName, 0x1);

      } 

    } while (_findnext(DirDone, &ffblk) == 0);

    _findclose(DirDone) ;

  }
}



/****************************************************************/
/* Build The Initial Artfact Index.htm                          */
/****************************************************************/
int PreIndex() 
{
  iHtmMode = 0 ;
  sprintf(HtmFile, "%s\\Index.htm\0", BACQDir) ;

  HtmHndl = fopen(HtmFile, "w") ;
  if(HtmHndl != NULL)
  {
    iHtmMode = 1 ;

    fprintf(HtmHndl, "<html><head><title>AChoir Artifacts</title></head>\n") ;
    fprintf(HtmHndl, "<body>\n") ;
    fprintf(HtmHndl, "<h2>Welcome to AChoir %s</h2>\n\n", Version) ;
    fprintf(HtmHndl, "<p>\n") ;
    fprintf(HtmHndl, "Below is an Index of the Artifacts gathered for Acquisition: <b>%s</b>\n\n", ACQName) ;
    fprintf(HtmHndl, "</p>\n\n") ;
    fprintf(HtmHndl, "<table width=900>\n") ;
    fprintf(HtmHndl, "<tr><td align=left>\n") ;
    fprintf(HtmHndl, "<button onclick=\"window.history.back()\">&lt;&lt;</button>\n") ;
    fprintf(HtmHndl, "</td><td align=center>\n") ;
    fprintf(HtmHndl, "<a href=file:./ target=AFrame> Root </a>\n") ;
  }
  else
  {
    fprintf(HtmHndl, "Err: Could not Create Artifact Index: %s\n", HtmFile) ;
    printf("Err: Could not Create Artifact Index: %s\n", HtmFile) ;
  }
}



/****************************************************************/
/* Binary Copy From, To                                         */
/****************************************************************/
int binCopy(char *FrmFile, char *TooFile) 
{
  size_t inSize, outSize;
  unsigned char Cpybuf[8192]; 
  int NBlox = 0 ;

  FILE* FrmHndl ;
  FILE* TooHndl ;

  //FILETIME ftCreate, ftAccess, ftWrite;

  if(access(FrmFile, 0) != 0)
  {
    fprintf(LogHndl, "Err: Source Copy File Not Found: \n %s\n", FrmFile) ;
    printf("Err: Source Copy File Not Found: \n %s\n", FrmFile) ;
  }
  else
  {
    /****************************************************************/
    /* Get the original TimeStamps                                  */
    /****************************************************************/
    stat(FrmFile, &Frmstat);

    /****************************************************************/
    /* The code below has been removed because it is flaky          */
    /*                                                              */
    /* This would normally be the best way to get source file       */
    /*  timestamps but since many artifacts are still open, it      */
    /*  fails.  I have opted to use stat() which is more reliable,  */
    /*  and write a FILETIME struct conversion routine.             */
    /****************************************************************/
    //FrmHndl = CreateFile(FrmFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    //if(FrmHndl == INVALID_HANDLE_VALUE)
    // printf("Could not Read Old File Dates: %d\n", GetLastError()) ;
    //else {
    //GetFileTime(FrmHndl, &ftCreate, &ftAccess, &ftWrite);
    //CloseHandle(FrmHndl) ; }


    /****************************************************************/
    /* Copy File Code                                               */
    /****************************************************************/
    FrmHndl = fopen(FrmFile, "rb") ;
    TooHndl = fopen(TooFile, "wb") ;

    if((FrmHndl != NULL) && (TooHndl != NULL))
    {
      while((inSize = fread(Cpybuf, 1, sizeof Cpybuf, FrmHndl)) > 0) 
      {
        printf("Inf: 8K Block: %d\r", NBlox++) ;

        outSize = fwrite(Cpybuf, 1, inSize, TooHndl);
        if(outSize < inSize)
        {
          /****************************************************************/
          /* Somethingwent wrong - Show an error and quit                 */
          /****************************************************************/
          if(ferror(TooHndl))
          {
            fprintf(LogHndl, "Err: Error Copying File (Output Error)\n") ;
            printf("Err: Error Copying File (Output Error)\n") ;
          }
          else
          {
            fprintf(LogHndl, "Err: Error Copying File (Disk Full)\n") ;
            printf("Err: Error Copying File (Disk full)\n") ;
          }
          break;
        }
      }

      fclose(FrmHndl) ;
      fclose(TooHndl) ;

      /****************************************************************/
      /* Re-Set the original TimeStamps on copied file                */
      /****************************************************************/
      Time_tToFileTime(Frmstat.st_atime, 1) ; 
      Time_tToFileTime(Frmstat.st_mtime, 2) ;
      Time_tToFileTime(Frmstat.st_ctime, 3) ;


      TooHndl = CreateFile(TooFile, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, 
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

      //SetFileTime(TooHndl, &ftCreate, &ftAccess, &ftWrite);
      SetFileTime(TooHndl, &ToCTime, &ToATime, &ToMTime);
      CloseHandle(TooHndl);


      /****************************************************************/
      /* MD5 The Files                                                */
      /****************************************************************/
      FileMD5(FrmFile) ;
      fprintf(LogHndl, "Inf: Source File MD5.....: %s\n", MD5Out) ;
      printf("Inf: Source File MD5.....: %s\n", MD5Out) ;

      FileMD5(TooFile) ;
      fprintf(LogHndl, "Inf: Destination File MD5: %s\n", MD5Out) ;
      printf("Inf: Destination File MD5: %s\n", MD5Out) ;
    }
    else
    {
      fprintf(LogHndl, "Err: Could Not Open File(s) for Copy\n") ;
      printf("Err: Could Not Open File(s) for Copy\n") ;
    }
  }
}


void Time_tToFileTime(time_t InTimeT, int whichTime)
{
  /****************************************************************/
  /* This convoluted piece of code is neccesary because           */
  /*  CreateFile (necessary for GetFileTime) is super Flaky, and  */
  /*  There is no API convert from time_t to SYSTEMTIME - Sigh... */
  /****************************************************************/
  struct tm  *convgtm ;      // First convert to a tm struct
  SYSTEMTIME convstm = {0} ; // Next copy everything to a SYSTEMTIME struct
  time_t cmpTime ;
  int wIsDST = -1 ;

  unsigned short wYear;
  unsigned short wMonth;
  unsigned short wDayOfWeek; 
  unsigned short wDay;
  unsigned short wHour;
  unsigned short wMinute;
  unsigned short wSecond;
  unsigned short wMilliseconds;

  /****************************************************************/
  /* First we Convert to tm struct                                */
  /****************************************************************/
  convgtm = gmtime(&InTimeT) ;


  /****************************************************************/
  /* Set DST to -1 and run gmtime to see if the time was DST      */
  /*  Why does DST EVEN MATTER in UTC?  Sigh....                  */
  /****************************************************************/
  convgtm->tm_isdst = -1 ;
  cmpTime = mktime(convgtm) ;


  /****************************************************************/
  /* Was it DST?  If so, add 3600  - I... Never Mind..            */
  /****************************************************************/
  wIsDST = convgtm->tm_isdst ;


  /****************************************************************/
  /* This was during DST - Subtract an hour and reconvert         */
  /****************************************************************/
  if(wIsDST == 0)
  {
    InTimeT = InTimeT - 3600 ;
    convgtm = gmtime(&InTimeT) ;
  }


  /****************************************************************/
  /* Get the data from the tm struct                              */
  /****************************************************************/
  wYear =   convgtm->tm_year + 1900 ;
  wMonth =  convgtm->tm_mon + 1 ;
  wDay =    convgtm->tm_mday ;
  wHour =   convgtm->tm_hour ;
  wMinute = convgtm->tm_min ;
  wSecond = convgtm->tm_sec ;


  /****************************************************************/
  /* Move it to the SYSTEMTIME struct                             */
  /****************************************************************/
  convstm.wYear  =  wYear ;
  convstm.wMonth =  wMonth ;
  convstm.wDay   =  wDay ;
  convstm.wHour  =  wHour ;
  convstm.wMinute = wMinute ;
  convstm.wSecond = wSecond ;


  /****************************************************************/
  /* CTime, ATime, MTime                                          */
  /****************************************************************/
  if(whichTime == 1)
   SystemTimeToFileTime(&convstm, &ToATime);
  else
  if(whichTime == 2)
   SystemTimeToFileTime(&convstm, &ToMTime);
  else
  if(whichTime == 3)
   SystemTimeToFileTime(&convstm, &ToCTime);
  else
   SystemTimeToFileTime(&convstm, &TmpTime);
}



/****************************************************************/
/* Console Input                                                */
/****************************************************************/
long consInput(char *consString)
{
  fprintf(LogHndl, "Inp: [%s]", consString) ;
  printf("Inp: %s", consString) ;

  memset(Conrec, 0, 255) ;
  fgets(Conrec, 251, stdin) ;
  strtok(Conrec, "\n") ; 
  strtok(Conrec, "\r") ; 

  /****************************************************************/
  /* If our input is too long, clear the rest over 250 chars      */
  /****************************************************************/
  if(strlen(Conrec) > 249)
  {
    fprintf(LogHndl, "Err: Input Truncated!\n") ;
    printf("Err: Input Truncated!\n");

    while ((getKey = getchar()) != '\n' && getKey != EOF);
  }

  fprintf(LogHndl, "%s\n", Conrec) ;
}



/****************************************************************/
/* Console Input                                                */
/****************************************************************/
long mapsDrive(char *mapString)
{
  memset(Conrec, 0, 255) ;
  if(strlen(mapString) < 1)
   consInput("Map: Server\\Share>") ;
  else
   strncpy(Conrec, mapString, 254) ;


  iGoodMap = 0 ;
  while(iGoodMap == 0)
  {
    fprintf(LogHndl, "Map: %s\n", Conrec) ;
    printf("Map: %s\n", Conrec) ;

    netRes.dwType = RESOURCETYPE_DISK;
    netRes.lpRemoteName = Conrec ;

    // netRC = WNetUseConnection(NULL, &netRes, NULL, NULL, Flags, szConnection, &ConnectSize, &ConnectResult);
    netRC = WNetUseConnection(NULL, &netRes, inPass, inUser, Flags, szConnection, &ConnectSize, &ConnectResult);

    if(netRC != NO_ERROR)
    {
      printf("Err: Error Mapping Resource: %s\n\n", Conrec);
      fprintf(LogHndl, "Err: Error Mapping Resource: %s\n\n", Conrec);

      printf("Map: Please Re-Enter Server\\Drive or \"quit\".\n");
      memset(Conrec, 0, 255) ;
      consInput("Map: Server\\Share>") ;

      if(strnicmp(Conrec, "quit", 4) == 0)
      {
        printf("Err: Program Exit Requested.\n");
        fprintf(LogHndl, "Err: Program Exit Requested.\n");
        exit (1);
      }
    }
    else
    {
       iGoodMap = 1 ;
       printf("Inf: Successfully Mapped %s to drive %s\n", Conrec, szConnection);
       fprintf(LogHndl, "Inf: Successfully Mapped %s to drive %s\n", Conrec, szConnection);
       strncpy(MapDrive, szConnection, 3) ;

       sprintf(BACQDir, "%s\\%s\0", szConnection, ACQName) ;
    }
  }
}


