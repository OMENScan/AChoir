/****************************************************************/
/* ACQRemote - Parse JSON and fire off remote AChoir - v0.01    */
/* v0.02     - JSON Config Options                              */
/* v0.03     - Add Logging                                      */
/* v0.04     - Add Extensive Debugging (Normal, Verbose, Absurd)*/
/* v0.05     - Add IP Auth and Multiple Run Types               */
/****************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/*#ifndef NO_UNISTD
#include <unistd.h>
#endif NO_UNISTD */

#include <conio.h>

#include <time.h>
#include <io.h>
#include <direct.h>
#include <process.h>

#include <windows.h>



/****************************************************************/
/*  Arrays of JSON Variables                                    */
/****************************************************************/
int  MaxArray = 10;
int  NumArray = 0;
char *JSONArray ;
char *DATAArray ;


/****************************************************************/
/*  Basic Variables                                             */
/****************************************************************/
int  JSNPoint = 0 ;
int  NXTPoint = 0 ;
int  DeBug    = 0 ; // 1=Basic, 2=Verbose

/****************************************************************/
/*  SMTP Variables                                              */
/****************************************************************/
int  SendSMTP = 0;
char AcqMailer[256]  = "C:\\Web\\Acq\\Prog\\ACQMail.exe\0" ;
char SMTPFrom[256]   = "Nobody@Nowhere\0" ;
char SMTPTo[256]     = "Nobody@Nowhere\0" ;


/****************************************************************/
/*  CGI Variables sent from the browser.  Make these GLOBAL     */
/****************************************************************/
char *UserName ;
char *MyIPAddr ;
char *Qstring  ;
char *CgiRoot  ;
char *InBuff   ;
char *Cookies  ;
char *ContentLengthS ;
int   ContentLengthI ;


/****************************************************************/
/*  Prototypes                                                  */
/****************************************************************/
void CGIGetIn(char *Varbl, char *Value, char *InBuff, int MaxSize, int EscProc) ;
void CookieGetIn(char *Varbl, char *Value, char *InBuff, int MaxSize) ;
void CGIError(char *BErrText, char *FErrText, char *Var1, char *Var2) ;
void JSNParse(char *Varbl, char *Value, char *InBuff, int MaxSize, int MaxBufSz);
void Xlate(char *XlateText) ;
void XlEsc(char *XlateText) ;
int MemAllocErr(char *ErrType) ;
void ACQLogger(char *ACQDate, char *ACQTime, char *AcqData, char *ACQVar) ;


/****************************************************************/
/*  Handles                                                     */
/****************************************************************/
FILE* ErrHndl   ;
FILE* LogHndl   ;
FILE* SklHndl   ;
FILE* SkeHndl   ;
FILE* IniHndl   ;
FILE* MailHndl  ;


/****************************************************************/
/*  Configuration File Names                                    */
/****************************************************************/
char ErrLog[256]     = "/Web/Acq/Log/Error.log\0"       ;
char LogLog[256]     = "/Web/Acq/Log/AcqRemote.log\0"    ;
char SklFile[256]    = "/Web/Acq/Config/ACQRemote.skl\0"   ;
char SkeFile[256]    = "/Web/Acq/Config/ACQRemote.err\0"   ;
char IniFile[256]    = "/Web/Acq/Config/ACQRemote.ini\0" ;

char MailFile[256]   = "/Web/Acq/Mail/123456.mll\0"     ;

char ACQTitle[256]   = "\0"         ;
char ACQBGClr[50]    = "#D8BFD8\0"  ;
char ACQFontClr[50]  = "#000000\0"  ;
char ACQLinkClr[50]  = "#FF0000\0"  ;
char ACQVLinkClr[50] = "Red\0"      ;
char ACQTableClr[50] = "#8CCECE\0"  ;
char ACQBordrClr[50] = "#000000\0"  ;
char ACQLightClr[50] = "#CCFFFF\0"  ;
char ACQDarkClr[50]  = "#CCFFFF\0"  ;
char ACQAdminMail[256] = "nobody@nowhere\0" ;


/****************************************************************/
/*  Triage Script/Program                                       */
/****************************************************************/
char AcqTriage[256]  = "C:\\Web\\Acq\\Prog\\ACQTriage.bat\0" ;
char FulTriage[2048]  = "C:\\Web\\Acq\\Prog\\ACQTriage.bat Parms\0" ;


char CDate[15] = "01/01/0001\0" ;
char CTime[15] = "01:01:00\0"   ;

char *InBuff   ;

int SessNum, SessThere  ;

char UserId[50]  = "\0" ;
char UserPW[50]  = "\0" ;
char Session[50] = "\0" ;

char FullName[256] = "ACHoir Remote\0" ;
char EmailAdd[256] = "nobody@nowhere\0" ;

char FullTooo[256] = "ACHoir Remote\0" ;
char EmailToo[256] = "nobody@nowhere\0" ;

char MailParms[256]   = "/Web/ACQ/Mail/123456.mll\0"     ;

int  gotType = 0;
char AcqType[15] = "Default\0" ;
char AcqTypx[15] = "[Default]\0" ;
char IPAuth[256] = "127.0.0.1\0" ;

int iMonth, iDay, iYear, iHour, iMin, iSec ;
unsigned long LCurrTime, LExpyTime  ;


int main(int argc, char *argv[])
{
  char *TokPtr, *Indx    ;
  int i, VarzCGI ;

  char Inrec[256]   ;
  char Outrec[256]  ;
  int  VarSz        ;
  int  oPtr, iPtr, KeepOn ;


  /**************************************************************/
  /* Pacific Standard Time & Daylight Savings                   */
  /**************************************************************/
  time_t timeval     ;
  struct tm *lclTime ;

  LCurrTime = time(NULL)     ;
  LExpyTime = LCurrTime+3200 ; // 60 Minutes Inactivity Max


  /************************************************************/
  /* Set the Time Zone and Daylight savings time, Then get    */
  /* The Date into a struct                                   */
  /*                                                          */
  /*        The current year is: %d\n", lclTime.tm_year       */
  /*        The current day is: %d\n", lclTime.tm_mday        */
  /*        The current month is: %d\n", lclTime.tm_mon	      */
  /************************************************************/
  time(&timeval)          ;
  lclTime = localtime(&timeval)  ;
  iMonth = lclTime->tm_mon+1     ;
  iDay   = lclTime->tm_mday      ;
  iYear  = lclTime->tm_year+1900 ;
  iHour  = lclTime->tm_hour      ;
  iMin   = lclTime->tm_min       ;
  iSec   = lclTime->tm_sec       ;

  sprintf(CTime, "%02d:%02d:%02d\0",
                 iHour, iMin, iSec);

  sprintf(CDate, "%02d/%02d/%d\0",
                 iMonth, iDay, iYear);


  /******************************************************************/
  /* Parse Env Variables                                            */
  /******************************************************************/
  if(DeBug > 0)
   ACQLogger(CDate, CTime, "ACQ: Parsing Environment Variables", " ");

  MyIPAddr       = getenv("REMOTE_ADDR")  ;
  UserName       = getenv("REMOTE_USER")  ;
  CgiRoot        = getenv("SCRIPT_NAME")  ;
  Cookies        = getenv("HTTP_COOKIE")  ;
  ContentLengthS = getenv("CONTENT_LENGTH") ;
  Qstring        = getenv("QUERY_STRING") ;


  if(DeBug > 0)
   ACQLogger(CDate, CTime, "ACQ: Remote IP Address", MyIPAddr);

  if(DeBug > 0)
   ACQLogger(CDate, CTime, "ACQ: Reading POST Data", " ");

  // Only do the atoi if there is something to convert
  // Otherwise the CGI will hang!  Arg!
  if(ContentLengthS)
   ContentLengthI = atoi(ContentLengthS) ;
  else
   ContentLengthI = 0 ;

  // Did We Specify a Type?
  if(argc > 1) 
  {
    memset(AcqType, 0, 15);
    memset(AcqTypx, 0, 15);
    strncpy(AcqType, argv[1], 10) ;
    sprintf(AcqTypx, "[%s]", AcqType) ;
  }


  /**************************************************************/
  /* Allocate JSON Array Memory                                 */
  /**************************************************************/
  if(DeBug > 0)
   ACQLogger(CDate, CTime, "ACQ: Allocating Memory", " ");

  NumArray = 0 ;

  JSONArray = (char *) malloc(MaxArray*256) ;
  if(JSONArray == NULL) 
   MemAllocErr("JSON Variable Array") ;

  DATAArray = (char *) malloc(MaxArray*256) ;
  if(DATAArray == NULL) 
   MemAllocErr("JSON Data Array") ;

  memset(JSONArray, 0, MaxArray*256) ;
  memset(DATAArray, 0, MaxArray*256) ;


  /************************************************************/
  /* Load up the Parms                                        */
  /************************************************************/
  if(DeBug > 0)
   ACQLogger(CDate, CTime, "ACQ: Reading Config File", " ");

  IniHndl = fopen(IniFile, "r") ;
  if(IniHndl != NULL)
  {
    gotType = 0;
    while(fgets(Inrec, 250, IniHndl))
    {
      // Look for a Signature Input
      strtok(Inrec, "\n") ;

      //Look for the [Section] we want to use
      if(strnicmp(Inrec, AcqTypx, 12) == 0)
      {
        gotType = 1 ;
        continue ;
      }


      //We found our section - Now pull the parameters
      if(gotType == 1)
      {
        if(strnicmp(Inrec, "[End]", 5) == 0)
         break ;
        else
        if(strnicmp(Inrec, "EMail:Yes", 9) == 0)
         SendSMTP = 1 ;
        else
        if(strnicmp(Inrec, "EMail:No", 8) == 0)
         SendSMTP = 0 ;
        else
        if(strnicmp(Inrec, "Mailer:", 7) == 0)
        {
          strncpy(AcqMailer, Inrec+7, 255)  ;
          AcqMailer[255] = '\0' ;
        }
        else
        if(strnicmp(Inrec, "Triage:", 7) == 0)
        {
          strncpy(AcqTriage, Inrec+7, 255)  ;
          AcqTriage[255] = '\0' ;
        }
        else
        if(strnicmp(Inrec, "SMTPTo:", 7) == 0)
        {
          strncpy(SMTPTo, Inrec+7, 255)  ;
          SMTPTo[255] = '\0' ;
        }
        else
        if(strnicmp(Inrec, "SMTPFrom:", 9) == 0)
        {
          strncpy(SMTPFrom, Inrec+9, 255)  ;
          SMTPFrom[255] = '\0' ;
        }
        else
        if(strnicmp(Inrec, "IPAuth:", 7) == 0)
        {
          strncpy(IPAuth, Inrec+7, 255)  ;
          IPAuth[255] = '\0' ;
        }
        else
        if(strnicmp(Inrec, "JSON:", 5) == 0)
        {
          if(NumArray < MaxArray)
          {
            strncpy(JSONArray+(NumArray*256), Inrec+5, 255) ;

            if(DeBug > 1)
             ACQLogger(CDate, CTime, "ACQ: Initializing JSON Variable:", JSONArray+(NumArray*256));

            NumArray++;
          }
          else
           printf("Max array size Exceeded: %d\n", MaxArray);
        }
      }
    }

    fclose(IniHndl) ;

  }
  else
   CGIError("ACQ: Could not read Configuration File",
            "ACQ: No Valid Configuration File Found", AcqType, " ")  ;


  if(gotType == 0)
   CGIError("ACQ: Invalid Triage Type",
            "ACQ: Triage Type Not Found: ", AcqType, " ")  ;


  if(strnicmp(MyIPAddr, IPAuth, 255) != 0)
   CGIError("ACQ: Not Authorized",
            "ACQ: Remote IP Address does not match Authorized IP:", MyIPAddr, IPAuth)  ;



  /**************************************************************/
  /* Read JSON from HTTP PUT                                    */
  /**************************************************************/
  if(DeBug > 0)
   ACQLogger(CDate, CTime, "ACQ: Parsing JSON Key/Value Pairs", ":");


  if(ContentLengthI > 1)
  {
    ContentLengthI++; // Pad for Null Terminator
    VarzCGI = 1 ;

    InBuff   = (char *) malloc(ContentLengthI)  ;
    memset(InBuff, 0, ContentLengthI);
    fread(InBuff, 1, ContentLengthI, stdin)   ;

    if(DeBug > 2)
     ACQLogger(CDate, CTime, "ACQ: Pre-Processed CGI Input Data Dump:", InBuff);

    XlEsc(InBuff);

    if(DeBug > 2)
     ACQLogger(CDate, CTime, "ACQ: Post Processed CGI Input Data Dump:", InBuff);


    /**************************************************************/
    /* Now bump through JSON Variables                            */
    /**************************************************************/
    if(DeBug > 0)
     ACQLogger(CDate, CTime, "ACQ: Searching CGI Input for JSON Variables", ":");

    for(i=0; i < NumArray; i++)
    {
      if(DeBug > 0)
       ACQLogger(CDate, CTime, "ACQ: JSON Variable:", JSONArray+(i*256));

      JSNPoint = 0 ;
      JSNParse(JSONArray+(i*256), DATAArray+(i*256), InBuff, 255, ContentLengthI) ;

      if(DeBug > 0)
       ACQLogger(CDate, CTime, "ACQ: Returned JSON Value: ", DATAArray+(i*256));
    }

  }
  else
    CGIError("ACQ: No Valid Input Data Was Read",
             "ACQ: No Valid Input Data Was Read", " ", " ")  ;



  /**************************************************************/
  /* Generate an Email                                          */
  /**************************************************************/
  if(DeBug > 0)
   ACQLogger(CDate, CTime, "ACQ: Generating EMail", " ");

  if(strlen(SMTPFrom) < 5)
    CGIError("ACQ: No From: Email Address Found in Configuration",
             "ACQ: From: Email Address was either blank or less than 5 characters: ", SMTPFrom, " ")  ;

  if(strlen(SMTPTo) < 5)
    CGIError("ACQ: No To: Email Address Found in Configuration",
             "ACQ: To: Email Address was either blank or less than 5 characters: ", SMTPTo, " ")  ;



  /**************************************************************/
  /* Make CgiRoot the Path to the next program(s)               */
  /**************************************************************/
  Indx = strrchr(CgiRoot, '/') ;
  CgiRoot[Indx-CgiRoot] = '\0' ;



  /************************************************************/
  /* Generate a Random Number for the File Name/Session Number*/
  /************************************************************/
  SessThere = 1    ;

  while(SessThere == 1)
  {
    srand( (unsigned)time( NULL ) ) ;
    SessNum = rand() ;

    sprintf(MailFile,  "/Web/ACQ/Mail/%d.mll\0", SessNum)  ;

    if(access(MailFile, 0) != 0)
     SessThere = 0 ;
  }  



  /**************************************************************/
  /* Use the Session Name as the email file name also...        */
  /**************************************************************/
  if(DeBug > 0)
   ACQLogger(CDate, CTime, "ACQ: Creating Email File", " ");

  MailHndl = fopen(MailFile, "w") ;
  if(MailHndl != NULL)
  {

    fprintf(MailHndl, "From:%s\n", SMTPFrom) ;
    fprintf(MailHndl, "To:<%s>\n", SMTPTo) ;
    fprintf(MailHndl, "Subj:Remote Triage Initated\n") ;

    fprintf(MailHndl, "DO NOT REPLY TO THIS EMAIL:\n" ) ;
    fprintf(MailHndl, "This Email was generated from the Automated Remote Triage System\n***\n\n" ) ;

    fprintf(MailHndl, "Message From: %s \n\n", SMTPFrom) ;
    fprintf(MailHndl, "Subject: Remote Triage Initated\n") ;
    fprintf(MailHndl, "Remote Triage Initated:\n\n") ;

    for(i=0; i < NumArray; i++)
    {
      fprintf(MailHndl, "%s%s\"\n", JSONArray+(i*256), DATAArray+(i*256)) ;
    }

    fprintf(MailHndl, "\n\n***\n" ) ;
    fprintf(MailHndl, "DO NOT REPLY TO THIS EMAIL:\n" ) ;
    fprintf(MailHndl, "This Email was generated from the Automated Remote Triage System\n" ) ;

    fclose(MailHndl) ;

  }
  else
    CGIError("ACQ: Error creating eMail Output.",
             "ACQ: Error Creating email Output File: ", MailFile, " ")  ;



  /************************************************************/
  /* Send Email                                               */
  /************************************************************/
  if(SendSMTP == 1)
  {
    if(DeBug > 0)
     ACQLogger(CDate, CTime, "ACQ: Sending Email", " ");

    fflush(stdout) ;
    sprintf(MailParms, "File:C:\\Web\\ACQ\\Mail\\%d.mll\0", SessNum) ;
    spawnlp(P_WAIT, AcqMailer, "ACQMail.EXE", MailParms, NULL);
    //unlink(MailFile) ;
  }


  /************************************************************/
  /* Return HTML                                              */
  /************************************************************/
  if(DeBug > 0)
   ACQLogger(CDate, CTime, "ACQ: Writing CGI Output to STDOut", " ");

  printf("Content-type: text/html\n\n") ;

  //Read the HTML Skeleton File and display.
  SklHndl = fopen(SklFile, "r") ;
  if(SklHndl != NULL)
  {
    while(fgets(Inrec, 250, SklHndl))
    {
      VarSz = strlen(Inrec)  ;
      Outrec[0] = '\0'       ;
      oPtr = 0               ;

      for(iPtr=0; iPtr < VarSz; iPtr++)
      {
        if(strnicmp(Inrec+iPtr, "&&SessNum", 9) ==0 )
        {
          sprintf(Outrec+oPtr, "%d", SessNum) ;
          oPtr = strlen(Outrec)         ;
          iPtr+= 8                      ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&Todate", 8) ==0 )
        {
          sprintf(Outrec+oPtr, "%d/%d/%d", iMonth, iDay, iYear) ;
           oPtr = strlen(Outrec)  ;
           iPtr+= 7               ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&EmailAdd", 10) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", EmailAdd) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 9               ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQBGClr", 10) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQBGClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 9               ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQFontClr", 12) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQFontClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 11              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQLinkClr", 12) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQLinkClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 11              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQVLinkClr", 13) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQVLinkClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 12              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQTableClr", 13) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQTableClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 12              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQBordrClr", 13) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQBordrClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 12              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQLightClr", 13) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQLightClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 12              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&Triage", 8) ==0 )
        {
          fflush(stdout) ;
          sprintf(FulTriage, "%s", AcqTriage);
          for(i =0; i < NumArray; i++)
          {
            if(strchr(DATAArray+(i*256), ' ') != NULL)
             strcat(FulTriage, " \"\0");
            else
             strcat(FulTriage, " \0");

            strcat(FulTriage, DATAArray+(i*256));

            if(strchr(DATAArray+(i*256), ' ') != NULL)
             strcat(FulTriage, "\"\0");
          }

          ACQLogger(CDate, CTime, "ACQ: Triage Initiated -", FulTriage);

          system(FulTriage) ;

          oPtr = strlen(Outrec)  ;
          iPtr+= 7              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&JSON", 6) ==0 )
        {
          for(i=0; i < NumArray; i++)
          {
            printf("%s%s\"<br>\n", JSONArray+(i*256), DATAArray+(i*256)) ;
          }
          oPtr = strlen(Outrec)  ;
          iPtr+= 5               ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&CGIRoot", 9) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", CgiRoot) ;
           oPtr = strlen(Outrec)  ;
           iPtr+= 8               ;
        }
        else
        {
          Outrec[oPtr] = Inrec[iPtr] ;
          oPtr++                     ;
          Outrec[oPtr] = '\0'        ;
        }
      }
      printf("%s", Outrec)  ;
    }

    fclose(SklHndl) ;
    fflush(stdout) ;
  }

  free(InBuff)      ;

  exit  (0) ;
  return 0  ;
}


/****************************************************************/
/* Look through the CGI input from STDIN and parse out the      */
/* Form Variable/Value Sets                                     */
/****************************************************************/
void CGIGetIn(char *Varbl, char *Value, char *InBuff, int MaxSize, int EscProc)
{
  int Iptr, Vptr, Xptr, DoMe, VarSz, nonBlank ;

  Vptr  = 0             ;
  VarSz = strlen(Varbl) ;
  for(Iptr=0; Iptr<ContentLengthI-1; Iptr++)
  {
    if(strnicmp(Varbl, InBuff+Iptr, VarSz) == 0)
    {
      DoMe  = 0      ;
      Vptr  = 0      ;
      nonBlank = 0   ;
      Iptr += VarSz  ;

      while(DoMe == 0)
      {
        if(Iptr > ContentLengthI-1) DoMe = 1  ;
        if(InBuff[Iptr] == '&')     DoMe = 1  ;
        if(Vptr > MaxSize-1)        DoMe = 1  ;

        // Did we reach the end of our input - Then iterate
        if(DoMe == 1) continue ;


        Value[Vptr]   = InBuff[Iptr] ;
        Value[Vptr+1] = '\0'         ;


        Vptr++   ;
        Iptr++   ;
      }

      if(strlen(Value) == 0)
       strcpy(Value, "(None) ") ;
      else
      {
        // Now UnEncode the CGI input
        if(EscProc == 1)
        {
          Xlate(Value) ;
        }
        else
        {
          XlEsc(Value) ;
        }


        // Check if Unencoded data is blank.
        for(Xptr=0; Xptr < strlen(Value); Xptr++)
        {
          if(Value[Xptr] != 32)
           if(Value[Xptr] != 10)
            if(Value[Xptr] != 13)
             nonBlank = 1 ;
        } 

        // Re-check for blank input.
        if(nonBlank == 0)
         strcpy(Value, "(None) ") ;

        if(strlen(Value) == 0)
         strcpy(Value, "(None) ") ;
      }
    }
  }

  // If no CGI Input AND no default set THEN set to (None) 
  if(strlen(Value) == 0)
   strcpy(Value, "(None) ") ;
}



/****************************************************************/
/* Turn the Munged Browser input into Understandable Input      */
/*   sanitize the input for HTML, JAVAscript and SQL injection  */
/****************************************************************/
void Xlate(char *XlateText)
{
  int TextSize         ;
  int Ptr1, Ptr2, XPtr ;
  char *XTable = "0123456789ABCDEF" ;
  int HexNum           ;
  int DidWe = 0        ;

  TextSize = strlen(XlateText) ;
  Ptr2 = 0                     ;


  /**************************************************************/
  /* Look Through the Passed string for CGI funky characters    */
  /**************************************************************/
  for(Ptr1=0; Ptr1 < TextSize; Ptr1++)
  {
    switch(XlateText[Ptr1])
    {

      /**********************************************************/
      /* What CGI REALLY means by a + is a space                */
      /**********************************************************/
      case '+':
      XlateText[Ptr2] = ' ' ;
      Ptr2++     ;
      break      ;

      /**********************************************************/
      /* Disallow any usage of a "'" (34) to avoid javascript   */
      /* and SQL injection                                      */
      /**********************************************************/
      case 34:
      XlateText[Ptr2] = ' ' ;
      Ptr2++     ;
      break      ;

      /**********************************************************/
      /* Disallow any usage of a "'" (39) to avoid javascript   */
      /* and SQL injection                                      */
      /**********************************************************/
      case 39:
      XlateText[Ptr2] = ' ' ;
      Ptr2++     ;
      break      ;

      /**********************************************************/
      /* Disallow any usage of a ";" (59) to avoid javascript   */
      /* injection                                              */
      /**********************************************************/
      case 59:
      XlateText[Ptr2] = ' ' ;
      Ptr2++     ;
      break      ;

      /**********************************************************/
      /* Disallow any usage of a "<"  to avoid HTML injection   */
      /**********************************************************/
      case 60:
      XlateText[Ptr2] = '[' ;
      Ptr2++     ;
      break      ;

      /**********************************************************/
      /* Disallow any usage of a ">"  to avoid HTML injection   */
      /**********************************************************/
      case 62:
      XlateText[Ptr2] = ']' ;
      Ptr2++     ;
      break      ;

      /**********************************************************/
      /* Disallow any usage of a "\" (92) to avoid javascript   */
      /* and SQL injection                                      */
      /**********************************************************/
      case 92:
      XlateText[Ptr2] = '/' ;
      Ptr2++     ;
      break      ;


      /**********************************************************/
      /* CGI wants to tell us that a special character is here  */
      /* But we DONT CARE!  WE WANT SPECIAL characters.  So go  */
      /* ahead and convert it back.                             */
      /**********************************************************/
      case '%':
      Ptr1++     ;
      HexNum = 0 ;
      DidWe = 1  ;
      for(XPtr=0; XPtr < 16; XPtr++)
      {
        if(XlateText[Ptr1] == XTable[XPtr])
           HexNum = XPtr*16 ;
      }

      Ptr1++     ;
      for(XPtr=0; XPtr < 16; XPtr++)
      {
        if(XlateText[Ptr1] == XTable[XPtr])
           HexNum += XPtr ;
      }

      // Disallow any usage of a "<" (60) 
      if(HexNum == 60)
        HexNum = 91 ;

      // Disallow any usage of a ">" (62) 
      if(HexNum == 62)
        HexNum = 93 ;

      // Disallow any usage of a ";" (59) 
      if(HexNum == 59)
        HexNum = 32 ;

      // Disallow any usage of a "'" (34) 
      if(HexNum == 34)
        HexNum = 32 ;

      // Disallow any usage of a "'" (39) 
      if(HexNum == 39)
        HexNum = 32 ;


      // Disallow any usage of a "\" (92) 
      if(HexNum == 92)
        HexNum = 47 ;


      XlateText[Ptr2] = HexNum ;
      Ptr2++     ;
      break      ;

      default:
      XlateText[Ptr2] = XlateText[Ptr1] ;
      Ptr2++     ;
      break      ;

    }
  }

  /**************************************************************/
  /* If we did any Conversion, wipe out the rest of the line    */
  /**************************************************************/
  if(DidWe == 1)
  {
    for(Ptr1=Ptr2; Ptr1 < TextSize; Ptr1++)
    {
      XlateText[Ptr1] = '\0' ;
    }
  }
}


/****************************************************************/
/* Turn the Munged Browser input into Understandable Input      */
/****************************************************************/
void XlEsc(char *XlateText)
{
  int TextSize         ;
  int Ptr1, Ptr2, XPtr ;
  char *XTable = "0123456789ABCDEF" ;
  int HexNum           ;
  int DidWe = 0        ;

  TextSize = strlen(XlateText) ;
  Ptr2 = 0                     ;


  /**************************************************************/
  /* Look Through the Passed string for CGI funky characters    */
  /**************************************************************/
  for(Ptr1=0; Ptr1 < TextSize; Ptr1++)
  {
    switch(XlateText[Ptr1])
    {

      /**********************************************************/
      /* What CGI REALLY means by a + is a space                */
      /**********************************************************/
      case '+':
      XlateText[Ptr2] = ' ' ;
      Ptr2++     ;
      break      ;


      /**********************************************************/
      /* CGI wants to tell us that a special character is here  */
      /* But we DONT CARE!  WE WANT SPECIAL characters.  So go  */
      /* ahead and convert it back.                             */
      /**********************************************************/
      case '%':
      Ptr1++     ;
      HexNum = 0 ;
      DidWe = 1  ;
      for(XPtr=0; XPtr < 16; XPtr++)
      {
        if(XlateText[Ptr1] == XTable[XPtr])
           HexNum = XPtr*16 ;
      }

      Ptr1++     ;
      for(XPtr=0; XPtr < 16; XPtr++)
      {
        if(XlateText[Ptr1] == XTable[XPtr])
           HexNum += XPtr ;
      }


      XlateText[Ptr2] = HexNum ;
      Ptr2++     ;
      break      ;

      default:
      XlateText[Ptr2] = XlateText[Ptr1] ;
      Ptr2++     ;
      break      ;

    }
  }

  /**************************************************************/
  /* If we did any Conversion, wipe out the rest of the line    */
  /**************************************************************/
  if(DidWe == 1)
  {
    for(Ptr1=Ptr2; Ptr1 < TextSize; Ptr1++)
    {
      XlateText[Ptr1] = '\0' ;
    }
  }
}


/****************************************************************/
/* Look through the Cookies input and parse out the             */
/* Form Variable/Value Sets                                     */
/****************************************************************/
void CookieGetIn(char *Varbl, char *Value, char *InBuff, int MaxSize)
{
  int Iptr, Vptr, DoMe, VarSz, Cooklen ;


  VarSz = strlen(Varbl) ;
  Cooklen = strlen(Cookies) ;
  for(Iptr=0; Iptr<Cooklen; Iptr++)
  {
    if(strnicmp(Varbl, InBuff+Iptr, VarSz) == 0)
    {
      DoMe  = 0 ;
      Vptr  = 0 ;
      Iptr += VarSz  ;

      while(DoMe == 0)
      {
        if(Iptr > Cooklen)          DoMe = 1  ;
        if(InBuff[Iptr] == ';')     DoMe = 1  ;
        if(Vptr > MaxSize)          DoMe = 1  ;

        Value[Vptr] = InBuff[Iptr] ;
        Vptr++   ;
        Iptr++   ;
      }

      if(strlen(Value) == 0)
       strcpy(Value, "(None)\0") ;
      else
      {
        Value[Vptr-1] = '\0' ;
        if(strlen(Value) == 0)
        strcpy(Value, "(None)\0") ;

      }
    }
  }
}


/****************************************************************/
/* Generic CGI Error Routine                                    */
/****************************************************************/
void CGIError(char *BErrText, char *FErrText, char *Var1, char *Var2)
{

  char Inrec[256]  ;
  char Outrec[256] ;
  int  i, VarSz, oPtr, iPtr   ;

  setvbuf(stdout, NULL, _IONBF, 0) ;
  printf("Content-type: text/html\n\n") ;


  //Read the Error Skeleton File and display.
  SkeHndl = fopen(SkeFile, "r") ;
  if(SkeHndl != NULL)
  {
    while(fgets(Inrec, 250, SkeHndl))
    {
      VarSz = strlen(Inrec)  ;
      Outrec[0] = '\0'       ;
      oPtr = 0               ;


      for(iPtr=0; iPtr < VarSz; iPtr++)
      {
        if(strnicmp(Inrec+iPtr, "&&SessNum", 9) ==0 )
        {
          sprintf(Outrec+oPtr, "%d", SessNum) ;
          oPtr = strlen(Outrec)         ;
          iPtr+= 8                      ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&Todate", 8) ==0 )
        {
          sprintf(Outrec+oPtr, "%d/%d/%d", iMonth, iDay, iYear) ;
           oPtr = strlen(Outrec)  ;
           iPtr+= 7               ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQBGClr", 10) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQBGClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 9               ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQFontClr", 12) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQFontClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 11              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQLinkClr", 12) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQLinkClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 11              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQVLinkClr", 13) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQVLinkClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 12              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQTableClr", 13) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQTableClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 12              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQBordrClr", 13) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQBordrClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 12              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQLightClr", 13) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", ACQLightClr) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 12              ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&ACQError", 10) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", BErrText) ;
          oPtr = strlen(Outrec)  ;
          iPtr+= 9               ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&JSON", 6) ==0 )
        {
          for(i=0; i < NumArray; i++)
          {
            printf("%s%s<br>\n", JSONArray+(i*256), DATAArray+(i*256)) ;
          }
          oPtr = strlen(Outrec)  ;
          iPtr+= 5               ;
        }
        else
        if(strnicmp(Inrec+iPtr, "&&CGIRoot", 9) ==0 )
        {
          sprintf(Outrec+oPtr, "%s", CgiRoot) ;
           oPtr = strlen(Outrec)  ;
           iPtr+= 8               ;
        }
        else
        {
          Outrec[oPtr] = Inrec[iPtr] ;
          oPtr++                     ;
          Outrec[oPtr] = '\0'        ;
        }
      }
      printf("%s", Outrec)  ;
    }

    fclose(SkeHndl) ;
    fflush(stdout) ;
  }

  ErrHndl = fopen(ErrLog, "at")  ;
  if(ErrHndl != NULL)
  {
	 fprintf(ErrHndl, "%s %s %s \n", FErrText, Var1, Var2)  ;
	 fclose(ErrHndl)                ;
  }
  exit(0) ;
}


/****************************************************************/
/* Look through the JSON input from STDIN and parse out the     */
/* Variable/Value Sets                                          */
/****************************************************************/
void JSNParse(char *Varbl, char *Value, char *InBuff, int MaxSize, int MaxBufSz)
{
  int Iptr, Vptr, Xptr, DoMe, VarSz, nonBlank ;

  if(DeBug > 1)
   ACQLogger(CDate, CTime, "ACQ: Parsing JSON Variable:", Varbl);

  Vptr  = 0             ;
  VarSz = strlen(Varbl) ;
  for(Iptr=JSNPoint; Iptr<MaxBufSz-1; Iptr++)
  {
    if(strnicmp(Varbl, InBuff+Iptr, VarSz) == 0)
    {
      DoMe  = 0      ;
      Vptr  = 0      ;
      nonBlank = 0   ;
      Iptr += VarSz  ;

      // Save new start point for next search (Array Searches)
      NXTPoint = Iptr;

      while(DoMe == 0)
      {
        if(Iptr > MaxBufSz-1)       DoMe = 1  ;
        if(InBuff[Iptr] == '"')     DoMe = 2  ;
        if(Vptr > MaxSize-1)        DoMe = 3  ;

        // Did we reach the end of our input - Then break out
        if(DoMe != 0) break ;


        Value[Vptr]   = InBuff[Iptr] ;
        Value[Vptr+1] = '\0'         ;


        Vptr++   ;
        Iptr++   ;

      }


      if(strlen(Value) == 0)
       strcpy(Value, "(None) ") ;
      else
      {
        // Check if data is blank.
        for(Xptr=0; Xptr < strlen(Value); Xptr++)
        {
          if(Value[Xptr] != 32)
           if(Value[Xptr] != 10)
            if(Value[Xptr] != 13)
             nonBlank = 1 ;
        } 

        // Re-check for blank input.
        if(nonBlank == 0)
         strcpy(Value, "(None) ") ;

        if(strlen(Value) == 0)
         strcpy(Value, "(None) ") ;
      }
    

      // Break out of the loop since we found our data.  This is so that 
      // we dont continue to parse out more entries in the array.
      break ;

    }
  }

  // If no JSN Input AND no default set THEN set to (None) 
  if(strlen(Value) == 0)
   strcpy(Value, "(None) ") ;

}


/***********************************************************/
/* Memory Allocation Problem                               */
/***********************************************************/
int MemAllocErr(char *ErrType)
{
  printf("Error Allocating Enough Memory For: %s\n", ErrType) ;

  ErrHndl = fopen(ErrLog, "at")  ;
  if(ErrHndl != NULL)
  {
    fprintf(ErrHndl, "\nError Allocating Enough Memory For: %s\n", ErrType)  ;
    fclose(ErrHndl)  ;
  }

  exit (1) ;
  return 1 ;
}


/****************************************************************/
/* Generic Logging Routine                                      */
/****************************************************************/
void ACQLogger(char *ACQDate, char *ACQTime, char *AcqData, char *ACQVar)
{
  LogHndl = fopen(LogLog, "at")  ;
  if(LogHndl != NULL)
  {
    fprintf(LogHndl, "%s %s %s %s\n", ACQDate, ACQTime, AcqData, ACQVar)  ;
    fclose(LogHndl) ;
  }
  return ;
}



