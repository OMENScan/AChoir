/****************************************************************/
/* CopyRight David V. Porco - March 2012 - All Rights Reserved  */
/*                                                              */
/* David Porco Mailer - 08/09/2009                              */
/*                                                              */
/* This is an SMTP Mailer - Written so I could fully understand */
/*  the SMTP and MIME protocols.                                */
/*                                                              */
/* My gratitude to the Public Domain BLAT mailer, from which I  */
/*  lifted a lof of this code.  But I needed something that     */
/*  would alow me to experiment more by creating input files    */
/*  instead of passed arguments.  Thus DVPMailer was born       */
/*                                                              */
/* Please Note: it currently only supports one MIME attachment. */
/*                                                              */
/* 02/24/2012 - For some reason the Blat Mime Code is buggy     */
/*  Thanks to some code by Bob Trower, the Mime Portion is now  */
/*  stable.  The code can be downloaded at sourceforge:         */
/*   Bob Trower 08/04/01                                        */
/*   http://base64.sourceforge.net/b64.                         */
/*                                                              */
/* 02/10/2013 - Add CC                                          */
/*                                                              */
/****************************************************************/
/*#ifndef NO_UNISTD
#include <unistd.h>
#endif NO_UNISTD */

#include <io.h>
#include <conio.h>
#include <process.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <winsock.h>
#include <ctype.h>
#include <direct.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <windows.h>

struct  sockaddr_in SockA ;
WSADATA WData ;
SOCKET  Sockit ;
int    RetCd ;         
int    SMTPAuth ;
char   IOChar ;
char   MailServer[255] = "0.0.0.0\0" ;
char   AuthId[255]     = "\0" ;
char   AuthPW[255]     = "\0" ;
char   *RecvDat ;
int DebugMe  = 0 ;int FromFlag = 0 ;int ToooFlag = 0 ; 
int SubjFlag = 0 ;int CCccFlag = 0 ;int MimeFlag = 0 ; 
long CCccCount = 0 ;
FILE* IniHndl ;FILE* MailHndl ;FILE* InclHndl ;FILE* MimeHndl ;
char MailFile[255] = "C:\\Web\\Acq\\Mail\\Mail.mlf\0" ;
char InclFile[255] = "C:\\Web\\Acq\\Mail\\Include.Dat\0" ;
char MimeFile[255] = "C:\\Web\\Acq\\Mail\\Mime.in\0" ;
char MimeFnam[100] = "Mime.in\0" ; 
char Inrec[255] ;
char Blanks[15] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ;
char CrLf[5] = "\r\n\0" ;
struct stat statbuf ;
long   LFileSize ;

char IniFile[256]   = "/Web/Acq/Config/ACQRemote.ini\0" ;

void DoDebug(char *DebugFlag, char *DebugData, char *DebugParm1)
{
  char OutCon[80] = "\0" ;
  long Ptr, Lng ; 
  if(DebugMe == 1)
  {
    Lng = strlen(DebugData) ;
    if(Lng > 75) 
     Lng = 75 ;

    strcpy(OutCon+Lng, "...\0\0") ;

    for(Ptr=0; Ptr<Lng; Ptr++)
    {
      if(DebugData[Ptr] < 32) 
       OutCon[Ptr] = '\0' ;
      else
       OutCon[Ptr] = DebugData[Ptr] ;
    }
    printf( "\r%s %s %s\n", DebugFlag, OutCon, DebugParm1) ;
  }
}



int SMTPReply(SOCKET SMTPSok, char *SMTPString, char *ErrorString)
{
  int SMTPRepRC ;
  strncpy(RecvDat,"\0\0\0\0\0", 5) ;
  SMTPRepRC=recv(SMTPSok, RecvDat, 10000, 0);
  DoDebug(">", RecvDat, "") ;

  if(strnicmp(RecvDat, SMTPString, strlen(SMTPString)) != 0)
  {
    if(DebugMe !=2) 
     printf("\r%s\n", ErrorString) ;

    return(1) ;
  }
  else
   return(0) ;
}



int CleanUp(int CleanFlag)
{
  int CleanRc ;
  if(CleanFlag > 0)
   free(RecvDat) ;

  if(CleanFlag > 1)
  {
    CleanRc = close(Sockit) ;

    if(CleanRc == -1) 
     if(DebugMe != 2) 
      printf( "\r* Could not close socket...\n");
  }
  if(DebugMe !=2) 
   printf( "\r* Processing Complete, Now Exiting...\n");

  return(0) ;
}



long Squish(char *SqString)
{
  long Sqi, SqLen ;

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


static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


void encodeblock(unsigned char in[3], unsigned char out[4], int len )
{
  out[0] = cb64[ in[0] >> 2 ];
  out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
  out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
  out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}



void M64_Encode(char *inFile)
{
  unsigned char in[3], out[4];
  int i, len, blocksout = 0;
  int linesize = 72 ;
  FILE* inMHndl ;

  DoDebug("*", "Converting File to MIME:", inFile) ;

  inMHndl = fopen(inFile, "rb") ;

  if(inMHndl != NULL)
  {
    while(!feof(inMHndl)) 
    {
      len = 0;
      for( i = 0; i < 3; i++ ) 
      {
        in[i] = (unsigned char) getc(inMHndl);

        if(!feof(inMHndl)) 
         len++;
        else
         in[i] = 0;
      }

      if(len) 
      {
        encodeblock(in, out, len);
        RetCd = send(Sockit, out, 4, 0);
        blocksout++;
      }
      if( blocksout >= (linesize/4) || feof(inMHndl)) 
      {
        if(blocksout) 
         RetCd = send(Sockit, CrLf, 2, 0);

        blocksout = 0;
      }
    }
    fclose(inMHndl) ;
  }
}



int main (int argc, const char *argv[])
{
  int GoodMsg       ;
  char SMTPFrom[1024]  = "Nobody@Nowhere\0" ;
  char SMTPTooo[1024]  = "Nobody@Nowhere\0" ;
  char SMTPCCcc[1024]  = "Nobody@Nowhere\0" ;
  char SMTPSubj[1024]  = "<None>\0" ;
  char SMTPTime[1024]  = "Mon, 29 Jun 94 02:15:23 GMT\0" ;

  long i ;
  struct hostent *Host ;
  char   host_name[255] ;
  int    ccode, SockRC ;

  SYSTEMTIME             curtime ;
  TIME_ZONE_INFORMATION  tzinfo ;
  DWORD                  retval ; 

  char boundary[23] ;
  char abclist[63]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  char * days[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"} ;
  char * months[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"} ;
  char WhatZone[255] ;
  char SmalZone[10] = "GMT\0" ;

  time_t timeval ;
  struct tm *lclTime ;
  int iMonth, iDay, iYear, iHour, iMin, iSec, iWday ;

  srand(time(NULL));

  for (i=0 ; i<=20 ; i++ )
   boundary[i] = abclist[rand()%62] ;

  boundary[21]=0;

  time(&timeval) ;
  lclTime = localtime(&timeval) ;
  iMonth = lclTime->tm_mon+1 ;
  iDay   = lclTime->tm_mday ;
  iYear  = lclTime->tm_year+1900 ;

  if(iYear < 1950) iYear+=100 ;
  iHour  = lclTime->tm_hour ;
  iMin   = lclTime->tm_min ;
  iSec   = lclTime->tm_sec ;
  iWday  = lclTime->tm_wday ;

  GetLocalTime( &curtime ) ;
  retval = GetTimeZoneInformation( &tzinfo ) ;


  for(i=0;i<32;i++)
  {
    if(retval == TIME_ZONE_ID_STANDARD )
     WhatZone[i] = (char) tzinfo.StandardName[i] ;
    else 
     WhatZone[i] = (char) tzinfo.DaylightName[i];
  }

  if(strnicmp(WhatZone, "Pacific Daylight Time", 21) == 0)
   strncpy(SmalZone, "PDT\0", 4) ;
  else
  if(strnicmp(WhatZone, "Pacific Standard Time", 21) == 0)
   strncpy(SmalZone, "PST\0", 4) ;   

  sprintf (SMTPTime, "%s, %.2d %s %.2d %.2d:%.2d:%.2d %s", days[iWday], iDay, months[iMonth-1], iYear, iHour, iMin, iSec, SmalZone) ;
  SMTPAuth = 0 ;

  for (i=0; i<1024; i++)
  {
    SMTPFrom[i] = '\0' ;
    SMTPTooo[i] = '\0' ;
    SMTPCCcc[i] = '\0' ;
  }



  /************************************************************/
  /* Load up the ACQMail Parms from ACQRemote.ini             */
  /************************************************************/
  GoodMsg = TRUE ;

  DoDebug("*", "Reading Ini File:", IniFile) ;

  for (i=1; i<argc; i++)
  {
    if(strnicmp(argv[i], "OCfg:", 5) == 0)
    {
      if(strlen(argv[i]) > 1000)
      {
        GoodMsg = FALSE ;
        printf ("\r* ACQMail Configuration Argument Too Long.  Send Bypassed!\n") ;

        exit (0) ;
        return 0 ;
      }
      else
      {
        strcpy(IniFile, argv[i]+5) ;
      } 
    }
  }



  /************************************************************/
  /* Load up the Parms                                        */
  /************************************************************/
  IniHndl = fopen(IniFile, "r") ;
  if(IniHndl != NULL)
  {
    while(fgets(Inrec, 250, IniHndl))
    {
      // Look for a Signature Input
      strtok(Inrec, "\n") ;

      if(strnicmp(Inrec, "AuthId:", 7) == 0)
      {
        SMTPAuth = 1;

        strncpy(AuthId, Inrec+7, 255) ;
        AuthId[255] = '\0' ;

        DoDebug("*", "Auth ID:", AuthId) ;
      }
      else
      if(strnicmp(Inrec, "AuthPW:", 7) == 0)
      {
        SMTPAuth = 1;

        strncpy(AuthPW, Inrec+7, 255) ;
        AuthPW[255] = '\0' ;

        DoDebug("*", "Auth PW:", AuthPW) ;
      }
      else
      if(strnicmp(Inrec, "SMTPFrom:", 9) == 0)
      {
        strncpy(SMTPFrom, Inrec+9, 1000)  ;
        SMTPFrom[1000] = '\0' ;
      }
      else
      if(strnicmp(Inrec, "SMTPTo:", 7) == 0)
      {
        strncpy(SMTPTooo, Inrec+7, 1000)  ;
        SMTPTooo[1000] = '\0' ;
      }
      else
      if(strnicmp(Inrec, "SMTPCC:", 7) == 0)
      {
        strncpy(SMTPCCcc, Inrec+7, 1000) ;
        SMTPCCcc[1000] = '\0' ;
      }
      else
      if(strnicmp(Inrec, "SMTP:", 5) == 0)
      {
        strncpy(MailServer, Inrec+5, 255) ;
        MailServer[255] = '\0' ;

        DoDebug("*", "Mail Server:", MailServer) ;
      }
      else
      if(strnicmp(Inrec, "Debug:Yes", 9) == 0)
      {
        DebugMe = 1 ;
        DoDebug("*", "Debug Mode is:", "Yes") ;
      }
      else
      if(strnicmp(Inrec, "Debug:No", 8) == 0)
      {
        DebugMe = 0 ;
        DoDebug("*", "Debug Mode is:", "No") ;
      }
      else
      if(strnicmp(Inrec, "Debug:Quiet", 11) == 0)
      {
        DebugMe = 2 ;
        DoDebug("*", "Debug Mode is:", "Quiet") ;
      }
    }

    fclose(IniHndl) ;

  }
  else
  {
    printf("\rCould Not Read Configuration File: %s\n", IniFile) ;
    exit (0) ;
    return 0 ;
  }



  if(DebugMe !=2)
   printf ("\r* Program Execution Beginning...\n") ;

  GoodMsg = TRUE ;
  for (i=1; i<argc; i++)
  {
    if(strnicmp(argv[i], "From:", 5) == 0)
    {
      if(strlen(argv[i]) > 1024)
      {
        GoodMsg = FALSE ;

        if(DebugMe !=2)
         printf ("\r* From Argument Too Long.  Ignored!\n") ;
      }
    }
    else
    if(strnicmp(argv[i], "To:", 3) == 0)
    {
      if(strlen(argv[i]) > 1024)
      {
        GoodMsg = FALSE ;

        if(DebugMe !=2)
         printf ("\r* To Argument Too Long.  Ignored!\n") ;
      }
    }
    else
    if(strnicmp(argv[i], "Subj:", 5) == 0)
    {
      if(strlen(argv[i]) > 1024)
      {
        GoodMsg = FALSE ;

        if(DebugMe !=2)
         printf ("\r* Subject Argument Too Long.  Ignored!\n") ;
      }
    }
    else
    if(strnicmp(argv[i], "Serv:", 5) == 0)
    {
      if(strlen(argv[i]) > 250)
      {
        GoodMsg = FALSE ;

        if(DebugMe !=2)
         printf ("\r* Mail Server Argument Too Long.  Ignored!\n") ;
      }
    }
    else
    if(strnicmp(argv[i], "File:", 5) == 0)
    {
      if(strlen(argv[i]) > 250)
      {
        GoodMsg = FALSE ;

        if(DebugMe !=2)
         printf ("\r* Input Mail File Argument Too Long.  Ignored!\n") ;
      }
    }
  }


  if(GoodMsg == FALSE)
  {
    printf ("\r* Message Not Sent!\n") ;
    return(1) ;
  }


  if((RecvDat = malloc(10000)) == NULL)
  {
    printf ("\r* Could Not Allocate Memory for Receive Buffer...\n") ;
    printf ("\r* Message Not Sent!\n") ;
    return(3) ;
  }


  for (i=1; i<argc; i++)
  {
    if(strnicmp(argv[i], "From:", 5) == 0)
    {
      FromFlag = 1 ;
      strcpy(SMTPFrom, argv[i]+5) ;

      if(DebugMe !=2)
       printf ("\r* From: %s\n", SMTPFrom) ;
    }
    else
    if(strnicmp(argv[i], "To:", 3) == 0)
    {
      ToooFlag = 1 ;
      strcpy(SMTPTooo, argv[i]+3) ;

      if(DebugMe !=2)
       printf ("\r* To: %s\n", SMTPTooo) ;
    }
    else
    if(strnicmp(argv[i], "CC:", 3) == 0)
    {
      CCccFlag = 1 ;
      strcpy(SMTPCCcc, argv[i]+3) ;

      if(DebugMe !=2)
       printf ("\r* CC: %s\n", SMTPCCcc) ;
    }
    else
    if(strnicmp(argv[i], "Subj:", 5) == 0)
    {
      SubjFlag = 1 ;
      strcpy(SMTPSubj, argv[i]+5) ;

      if(DebugMe !=2)
       printf ("\r* Subj: %s\n", SMTPSubj) ;
    }
    else
    if(strnicmp(argv[i], "Serv:", 5) == 0)
    {
      strcpy(MailServer, argv[i]+5) ;

      if(DebugMe !=2)
       printf ("\r* MailServer: %s\n", MailServer) ;
    }
    else
    if(strnicmp(argv[i], "File:", 5) == 0)
    {
      strcpy(MailFile, argv[i]+5) ;

      DoDebug("*", "Input Mail File:", MailFile) ;
    }
  }


  DoDebug("*", "Getting header information From the Message File:", MailFile) ;

  MailHndl = fopen(MailFile, "r") ;
  if(MailHndl != NULL)
  {
    while(fgets(Inrec, 250, MailHndl))
    {
      Squish(Inrec) ;  

      if((strnicmp(Inrec, "From:", 5) == 0) && (FromFlag == 0))
      {
        FromFlag = 1 ;
        strcpy(SMTPFrom, Inrec+5) ;

        if(DebugMe !=2)
         printf ("\r* From: %s\n", SMTPFrom) ;
      }
      else
      if((strnicmp(Inrec, "To:", 3) == 0) && (ToooFlag == 0))
      {
        ToooFlag = 1 ;
        strcpy(SMTPTooo, Inrec+3) ;

        if(DebugMe !=2)
         printf ("\r* To: %s\n", SMTPTooo) ;
      }
      else
      if((strnicmp(Inrec, "CC:", 3) == 0) && (CCccFlag == 0))
      {
        CCccFlag = 1 ;
        strcpy(SMTPCCcc, Inrec+3) ;

        if(DebugMe !=2)
         printf ("\r* CC: %s\n", SMTPCCcc) ;
      }
      else
      if((strnicmp(Inrec, "Subj:", 5) == 0) && (SubjFlag == 0))
      {
        SubjFlag = 1 ;
        strcpy(SMTPSubj, Inrec+5) ;

        DoDebug("*", "Subject:", SMTPSubj) ;
      }
      else
      if(strnicmp(Inrec, "~Attach:", 8) == 0)
      {
        if(MimeFlag == 1)
        {
          if(DebugMe !=2)
           printf ("\r* Currently, Only a Single Attachment is supported\n", "") ;
        }
        else
        {
          strncpy(MimeFile, Inrec+8, 255) ;
          strncpy(MimeFnam, Inrec+8, 100) ;
          MimeFile[255]= '\0' ;
          MimeFnam[100]= '\0' ;

          for (i=0; i<strlen(MimeFile); i++)
          {
            if((MimeFile[i] == '/') || (MimeFile[i] == '\\'))
             strcpy(MimeFnam, MimeFile+i+1) ;
          }

          DoDebug("*", "Verifying MIME attachment:", MimeFile) ;

          MimeHndl = fopen(MimeFile, "rb") ;
          if(MimeHndl != NULL)
          {
            MimeFlag = 1 ;
            fclose(MimeHndl) ;

            DoDebug("*", "MIME attachment Verified:", MimeFile) ;
          }
          else
           DoDebug("*", "MIME attachment FAILED!:", MimeFile) ;
        }
      }
    }
    fclose(MailHndl) ;
  }



  if(FromFlag == 0)
  {
    if(DebugMe !=2)
     printf( "\r* No From: - Program Exiting without sending...\n");

    CleanUp(1) ;
    return(14) ;
  }


  if(ToooFlag == 0)
  {
    if(DebugMe !=2)
     printf( "\r* No To: - Program Exiting without sending...\n");

    CleanUp(1) ;
    return(15) ;
  }

  DoDebug("*", "Now Setting up Socket...", "") ;

  WSAStartup (0x101, &WData);

  DoDebug("*", "Openning Up Socket...", "") ;


  Sockit = socket(AF_INET, SOCK_STREAM,0);
  if(Sockit == -1) 
  {
    printf( "\r* Could not Open Socket.\n");
    CleanUp(1) ;
    return(5) ;
  }

  DoDebug("*", "Populating Socket Control Block...", "") ;

  SockA.sin_family=AF_INET;
  SockA.sin_port = htons(25);
  SockA.sin_addr.s_addr = inet_addr(MailServer);

  if( SockA.sin_addr.s_addr == -1 ) 
  {
    printf( "\r* Could not connect to Mail Server: %s\n", MailServer);
    CleanUp(1) ;
    return(4) ;
  }

  SockRC = gethostname(host_name, 250);
  if(SockRC != 0)
  {
    if(DebugMe !=2)
     printf( "\r* Unable to get My Hostname, ccode = %d, Check your DNS.\n", SockRC);
    CleanUp(1) ;
    return(16) ;
  }
  else 
  if(DebugMe !=2)
   printf( "\r* My Host Name: %s\n", host_name);

  DoDebug("*", "Connecting to Mail Server:", MailServer) ;

  RetCd = connect( Sockit, (struct sockaddr *) &SockA, sizeof(SockA));
  if( RetCd == -1 ) 
  {
    printf( "\r* Could not connect to Mail Server: %s\n", MailServer);
    CleanUp(2) ;
    return(6) ;
  }


  DoDebug("*", "Connected to Mail Server:", MailServer);

  if(SMTPReply(Sockit, "220", "* SMTP Host Not Responding...") != 0)
  {
    CleanUp(2) ;
    return(7) ;
  }

  sprintf(RecvDat,"HELO %s\r\n", host_name);

  DoDebug("<", RecvDat, "") ;

  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
  if(SMTPReply(Sockit, "250", "* Invalid response from SMTP Host...") != 0)
  {
    CleanUp(2) ;
    return(8) ;
  }


  if(SMTPAuth == 1)
  {
    sprintf(RecvDat,"auth login\n"); 
    DoDebug("<", RecvDat, "") ;

    RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
    if(SMTPReply(Sockit, "334", "* Invalid response from SMTP Host...") != 0)
    {
      CleanUp(2) ;
      return(8) ;
    }

    sprintf(RecvDat,"%s\n", AuthId);
    DoDebug("<", RecvDat, "") ;

    RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
    if(SMTPReply(Sockit, "334", "* Invalid response from SMTP Host...") != 0)
    {
      CleanUp(2) ;
      return(8) ;
    }

    sprintf(RecvDat,"%s\n", AuthPW);
    DoDebug("<", RecvDat, "") ;

    RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
    if(SMTPReply(Sockit, "235", "* Invalid response from SMTP Host...") != 0)
    {
      CleanUp(2) ;
      return(8) ;
    }
  }

  sprintf(RecvDat,"MAIL FROM:%s\r\n", SMTPFrom);
  DoDebug("<", RecvDat, "") ;
  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
  if(SMTPReply(Sockit, "250", "* Invalid response from SMTP Host...") != 0)
  {
    CleanUp(2) ;
    return(9) ;
  }


  // To: From Config Database
  if(SMTPTooo[0] == 60) 
   sprintf(RecvDat,"RCPT TO: %s\r\n", SMTPTooo);
  else
   sprintf(RecvDat,"RCPT TO: <%s>\r\n", SMTPTooo);

  DoDebug("<", RecvDat, "") ;

  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

  if(SMTPReply(Sockit, "250", "* Invalid response from SMTP Host...") != 0)
  {
    CleanUp(2) ;
    return(10) ;
  }


  DoDebug("*", "Reading Message File:", MailFile) ;

  MailHndl = fopen(MailFile, "r") ;
  if(MailHndl != NULL)
  {
    while(fgets(Inrec, 250, MailHndl))
    {
      Squish(Inrec) ;  

      if(strnicmp(Inrec, "CC:", 3) == 0)
      {
        strcpy(SMTPCCcc, Inrec+3) ;

        if(SMTPCCcc[0] == 60)
         sprintf(RecvDat,"RCPT TO: %s\r\n", SMTPCCcc);
        else
         sprintf(RecvDat,"RCPT TO: <%s>\r\n", SMTPCCcc);

        CCccFlag = 1 ;
        CCccCount += strlen(SMTPCCcc) ;

        if(DebugMe !=2)
         printf ("\r* CC: %s\n", SMTPCCcc) ;

        DoDebug("<", RecvDat, "") ;

        RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
        if(SMTPReply(Sockit, "250", "* Invalid response from SMTP Host...") != 0)
        {
          DoDebug("*", "Error Sending CC: Address - Ignored:", SMTPCCcc) ;
        }
      }
    }
  }

  strcpy(RecvDat,"DATA\r\n");

  DoDebug("<", RecvDat, "") ;
  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

  if(SMTPReply(Sockit, "354", "* The SMTP Host is not accepting the message...") != 0)
  {
    CleanUp(2) ;
    return(11) ;
  }
        
  strcpy(RecvDat, "X-Mailer: AChoirMailer v1.0\r\n");
  DoDebug("<", RecvDat, "") ;
  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

  sprintf(RecvDat, "From: %s\r\n", SMTPFrom);
  DoDebug("<", RecvDat, "") ;
  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

  sprintf(RecvDat, "To: %s\r\n", SMTPTooo);
  DoDebug("<", RecvDat, "") ;
  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

  if((CCccFlag == 1) && (MailHndl != NULL))
  {
    strcpy(RecvDat, "\0\0\0\0\0") ; 
    CCccCount = 0 ;

    rewind(MailHndl) ;

    while(fgets(Inrec, 250, MailHndl))
    {
      Squish(Inrec) ;  

      if(strnicmp(Inrec, "CC:", 3) == 0)
      {
        CCccCount += strlen(Inrec) ;
        if(CCccCount < 10000)
        {
          if(strlen(RecvDat) < 3)
           sprintf(RecvDat, "Cc: %s", Inrec+3);
          else
          {
            strcat(RecvDat, ",") ;
            strcat(RecvDat, Inrec+3) ;
          }
        }
      }
    }

    strcat(RecvDat, "\r\n\0") ;
    DoDebug("<", RecvDat, "") ;
    RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
  }

  sprintf(RecvDat, "Date: %s\r\n", SMTPTime);
  DoDebug("<", RecvDat, "") ;
  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

  if(MimeFlag == 1)
   sprintf(RecvDat, "Subject: %s\r\n", SMTPSubj) ;
  else
   sprintf(RecvDat, "Subject: %s\r\n\r\n", SMTPSubj);

  DoDebug("<", RecvDat, "") ;
  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

  if(MailHndl != NULL)
  {
    if(MimeFlag == 1)
    {
      DoDebug("*", "MIME eMail Output routine invoked", "") ;

      sprintf(RecvDat, "MIME-Version: 1.0\r\n") ;
      RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

      sprintf(RecvDat, "Content-Type: Multipart/Mixed; boundary=Mailer-%s\r\n\r\n", boundary) ;
      RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

      sprintf(RecvDat, "This eMail is in MIME format\nIf you are reading this message your eMail reader does not support MIME.\r\n") ;
      RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

      sprintf(RecvDat, "--Mailer-%s\r\n", boundary);
      RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

      sprintf(RecvDat, "Content-type: text/plain; charset=us-ascii\r\n\r\n");
      RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
    }

    rewind(MailHndl) ;

    while(fgets(Inrec, 250, MailHndl))
    {
      if((strlen(Inrec) == 1) && (Inrec[0] == '.'))
       strcpy(Inrec, "..\n\0") ;
      else
      if(strnicmp(Inrec, "CC:", 3) == 0)
       Squish(Inrec) ;
      else
      if(strnicmp(Inrec, "From:", 5) == 0)
       Squish(Inrec) ;
      else   
      if(strnicmp(Inrec, "To:", 3) == 0)
       Squish(Inrec) ;
      else   
      if(strnicmp(Inrec, "Subj:", 5) == 0)
       Squish(Inrec) ;
      else   
      if(strnicmp(Inrec, "~Include:", 9) == 0)
      {
        Squish(Inrec) ;  

        strcpy(InclFile, Inrec+9) ;

        DoDebug("*", "Include File:", InclFile) ;

        InclHndl = fopen(InclFile, "r") ;
        if(InclHndl != NULL)
        {
          while(fgets(Inrec, 250, InclHndl))
          {
            RetCd = send(Sockit, Inrec, strlen(Inrec), 0);
          }

          fclose(InclHndl) ;
        }
        else
        {
          sprintf(RecvDat, "\r\n<Include File: %s - Could not be opened>\r\n\r\n", InclFile);

          DoDebug("*", "Include File could not be opened:", InclFile) ;

          RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
        }
      }
      else   
      if(strnicmp(Inrec, "~Attach:", 8) == 0)
      {
        Squish(Inrec) ;  
        strcpy(InclFile, Inrec+8) ;

        DoDebug("*", "Attach File:", InclFile) ;

        InclHndl = fopen(InclFile, "r") ;
        if(InclHndl != NULL)
        {
          fclose(InclHndl) ;
        }
        else
        {
          sprintf(RecvDat, "\r\n<Attachment File: %s - Could not be opened>\r\n\r\n", InclFile);

          DoDebug("*", "Attachment File could not be opened:", InclFile) ;

          RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
        }
      }
      else   
      {
        RetCd = send(Sockit, Inrec, strlen(Inrec), 0);
      }
    }

    fclose(MailHndl) ;

    if(MimeFlag == 1)
    {
      sprintf(RecvDat, "\r\n--Mailer-%s\r\n", boundary);
      RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

      sprintf(RecvDat, "Content-Type: application/octet-stream; name=%s\r\n", MimeFnam);
      RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

      sprintf(RecvDat, "Content-Transfer-Encoding: BASE64\r\n\r\n");
      RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

      M64_Encode(MimeFile) ;

      sprintf(RecvDat, "\r\n--Mailer-%s--\r\n", boundary);
      RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
    }

    strcpy(RecvDat, "\r\n.\r\n");
    RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);
  }
  else
  {
    DoDebug("*", "Message not sent, Error Reading Message File:", MailFile) ;
    CleanUp(2) ;
    return(2) ;
  }

  if(SMTPReply(Sockit, "250", "* Invalid response from SMTP Host...") != 0)
  {
    CleanUp(2) ;
    return(12) ;
  }

  strcpy(RecvDat,"QUIT\r\n");
  DoDebug("<", RecvDat, "") ;
  RetCd = send(Sockit, RecvDat, strlen(RecvDat), 0);

  if(SMTPReply(Sockit, "221", "* Error Terminating the connection!") != 0)
  {
    CleanUp(2) ;
    return(13) ;
  }

  if(DebugMe !=2)
   printf("\r* Mail Message Sent Successfully!\n") ;

  CleanUp(2) ;
  Sockit = 0 ;
  return(0);
}
