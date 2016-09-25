// MFTAgain.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

// Not using winioctl.h lol!
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "ntfs.h"
#include "sqlite3.h"
#include <time.h>

#include <io.h>


// Global variables
ULONG BytesPerFileRecord;
HANDLE hVolume;
BOOT_BLOCK bootb;
PFILE_RECORD_HEADER MFT;

int  dbrc, dbMaxCol, dbRowCount, dbi;
int SpinLock;
char *dbMQuery; char *errmsg = 0; int dbMrc;
char *dbXQuery; int dbXrc; int dbXi;
char MFTDBFile[1024] = "C:\\AChoir\\Cache\\C-MFT.db\0";
char Str_Temp[1024] = "\0";
int MFT_Status = 0; // 0=Good, 1=NonFatal Error, 2=FatalError

sqlite3      *dbMFTHndl;
sqlite3_stmt *dbMFTStmt;
sqlite3_stmt *dbXMFTStmt;

int gotOwner = 0;
PSECURITY_DESCRIPTOR SecDesc = NULL;


// Template for padding
template <class T1, class T2> inline T1* Padd(T1* p, T2 n)
{
  return (T1*)((char *)p + n);
}


ULONG RunLength(PUCHAR run)
{
  //wprintf(L"In RunLength()...\n");
  return (*run & 0xf) + ((*run >> 4) & 0xf) + 1;
}


LONGLONG RunLCN(PUCHAR run)
{
  LONG i = 0;
  UCHAR n1 = 0, n2 = 0;
  LONGLONG lcn = 0;
  //wprintf(L"In RunLCN()...\n");
  n1 = *run & 0xf;
  n2 = (*run >> 4) & 0xf;
  lcn = n2 == 0 ? 0 : CHAR(run[n1 + n2]);
  for (i = n1 + n2 - 1; i > n1; i--)
    lcn = (lcn << 8) + run[i];
  return lcn;
}


ULONGLONG RunCount(PUCHAR run)
{
  UCHAR n = *run & 0xf;
  ULONGLONG count = 0;
  ULONG i;
  //wprintf(L"In RunCount()...\n");
  for (i = n; i > 0; i--)
    count = (count << 8) + run[i];
  return count;
}


BOOL FindRun(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, PULONGLONG lcn, PULONGLONG count)
{
  PUCHAR run = NULL;
  *lcn = 0;
  ULONGLONG base = attr->LowVcn;
  //wprintf(L"In FindRun()...\n");
  if (vcn < attr->LowVcn || vcn > attr->HighVcn)
    return FALSE;
  for (run = PUCHAR(Padd(attr, attr->RunArrayOffset)); *run != 0; run +=
    RunLength(run))
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
  //wprintf(L"FindAttribute() - Finding attributes...\n");
  for (attr = PATTRIBUTE(Padd(file, file->AttributesOffset));
    attr->AttributeType != -1; attr = Padd(attr, attr->Length))
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


PATTRIBUTE FindAttributeII(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, PWSTR name)
{
  PATTRIBUTE attr = NULL;
  int FoundAttr = 0;

  //wprintf(L"FindAttributeII() - Finding Second Attribute...\n");

  for (attr = PATTRIBUTE(Padd(file, file->AttributesOffset));
    attr->AttributeType != -1; attr = Padd(attr, attr->Length))
  {
    if (attr->AttributeType == type)
    {
      if (FoundAttr == 0)
        FoundAttr++;
      else
      {
        if (name == 0 && attr->NameLength == 0)
          return attr;
        if (name != 0 && wcslen(name) == attr->NameLength && _wcsicmp(name, PWSTR(Padd(attr, attr->NameOffset))) == 0)
          return attr;
      }
    }
  }
  return 0;
}


VOID FixupUpdateSequenceArray(PFILE_RECORD_HEADER file)
{
  ULONG i = 0;
  PUSHORT usa = PUSHORT(Padd(file, file->Ntfs.UsaOffset));
  PUSHORT sector = PUSHORT(file);
  //wprintf(L"In FixupUpdateSequenceArray()...\n");
  for (i = 1; i < file->Ntfs.UsaCount; i++)
  {
    sector[255] = usa[i];
    sector += 256;
  }
}


VOID ReadSector(ULONGLONG sector, ULONG count, PVOID buffer)
{
  ULARGE_INTEGER offset;
  OVERLAPPED overlap = { 0 };
  ULONG n;
  //wprintf(L"ReadSector() - Reading the sector...\n");
  //wprintf(L"Sector: %lu\n", sector);
  offset.QuadPart = sector * bootb.BytesPerSector;
  overlap.Offset = offset.LowPart;
  overlap.OffsetHigh = offset.HighPart;
  ReadFile(hVolume, buffer, count * bootb.BytesPerSector, &n, &overlap);
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

  //wprintf(L"ReadExternalAttribute() - Reading the Non resident attributes...\n");

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
  }
}


ULONG AttributeLength(PATTRIBUTE attr)
{
  //wprintf(L"In AttributeLength()...\n");
  return attr->Nonresident == FALSE ?
    PRESIDENT_ATTRIBUTE(attr)->ValueLength :
    ULONG(PNONRESIDENT_ATTRIBUTE(attr)->DataSize);
}


ULONG AttributeLengthAllocated(PATTRIBUTE attr)
{
  //wprintf(L"\nIn AttributeLengthAllocated()...\n");
  return attr->Nonresident == FALSE ?
    PRESIDENT_ATTRIBUTE(attr)->ValueLength :
    ULONG(PNONRESIDENT_ATTRIBUTE(attr)->AllocatedSize);
}


VOID ReadAttribute(PATTRIBUTE attr, PVOID buffer)
{
  PRESIDENT_ATTRIBUTE rattr = NULL;
  PNONRESIDENT_ATTRIBUTE nattr = NULL;
  //wprintf(L"ReadAttribute() - Reading the attributes...\n");
  if (attr->Nonresident == FALSE)
  {
    //wprintf(L"Resident attribute...\n");
    rattr = PRESIDENT_ATTRIBUTE(attr);
    memcpy(buffer, Padd(rattr, rattr->ValueOffset), rattr->ValueLength);
  }
  else
  {
    //wprintf(L"Non-resident attribute...\n");
    nattr = PNONRESIDENT_ATTRIBUTE(attr);
    ReadExternalAttribute(nattr, 0, ULONG(nattr->HighVcn) + 1, buffer);
  }
}


VOID ReadVCN(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, ULONGLONG vcn, ULONG count, PVOID buffer)
{
  PATTRIBUTE attrlist = NULL;
  PNONRESIDENT_ATTRIBUTE attr = PNONRESIDENT_ATTRIBUTE(FindAttribute(file, type, 0));
  //wprintf(L"In ReadVCN()...\n");
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
  //wprintf(L"ReadFileRecord() - Reading the file records..\n");

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
  wprintf(L"In LoadMFT() - Loading MFT...\n");
  BytesPerFileRecord = bootb.ClustersPerFileRecord < 0x80 
    ? bootb.ClustersPerFileRecord* bootb.SectorsPerCluster
    * bootb.BytesPerSector : 1 << (0x100 - bootb.ClustersPerFileRecord);
  wprintf(L"\nBytes Per File Record = %u\n\n", BytesPerFileRecord);
  wprintf(L"======THESE INFO ARE NOT ACCURATE FOR DISPLAY LOL!=====\n");
  wprintf(L"bootb.BootSectors = %u\n", bootb.BootSectors);
  wprintf(L"bootb.BootSignature = %u\n", bootb.BootSignature);
  wprintf(L"bootb.BytesPerSector = %u\n", bootb.BytesPerSector);
  wprintf(L"bootb.ClustersPerFileRecord = %u\n", bootb.ClustersPerFileRecord);
  wprintf(L"bootb.ClustersPerIndexBlock = %u\n", bootb.ClustersPerIndexBlock);
  wprintf(L"bootb.Code = %u\n", bootb.Code);
  wprintf(L"bootb.Format = %u\n", bootb.Format);
  wprintf(L"bootb.Jump = %u\n", bootb.Jump);
  wprintf(L"bootb.Mbz1 = %u\n", bootb.Mbz1);
  wprintf(L"bootb.Mbz2 = %u\n", bootb.Mbz2);
  wprintf(L"bootb.Mbz3 = %u\n", bootb.Mbz3);
  wprintf(L"bootb.MediaType = 0X%X\n", bootb.MediaType);
  wprintf(L"bootb.Mft2StartLcn = 0X%.8X\n", bootb.Mft2StartLcn);
  wprintf(L"bootb.MftStartLcn = 0X%.8X\n", bootb.MftStartLcn);
  wprintf(L"bootb.NumberOfHeads = %u\n", bootb.NumberOfHeads);
  wprintf(L"bootb.PartitionOffset = %lu\n", bootb.PartitionOffset);
  wprintf(L"bootb.SectorsPerCluster = %u\n", bootb.SectorsPerCluster);
  wprintf(L"bootb.SectorsPerTrack = %u\n", bootb.SectorsPerTrack);
  wprintf(L"bootb.TotalSectors = %lu\n", bootb.TotalSectors);
  wprintf(L"bootb.VolumeSerialNumber = 0X%.8X%.8X\n\n", bootb.VolumeSerialNumber.HighPart, bootb.VolumeSerialNumber.HighPart);

  MFT = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);

  ReadSector((bootb.MftStartLcn)*(bootb.SectorsPerCluster), (BytesPerFileRecord) / (bootb.BytesPerSector), MFT);

  FixupUpdateSequenceArray(MFT);
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
  int Str_Len, Max_Files;
  int Progress, ProgUnit;
  int File_RecNum, Dir_PrevNum, File_RecID;
  int MoreDirs, UseName;

  ULONGLONG File_CreDate, File_AccDate, File_ModDate;
  char Text_CreDate[30] = "\0";
  char Text_AccDate[30] = "\0";
  char Text_ModDate[30] = "\0";
  char Text_DateTyp[5] = "\0";

  ReadAttribute(attr, bitmap);
  
  ULONG n = AttributeLength(FindAttribute(MFT, AttributeData, 0)) / BytesPerFileRecord;
  ProgUnit = n / 50;

  wprintf(L"FindActive() - Finding the active files...\nooooooooooooooooooooooooooooooooooooooooooooooooo\r");

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

    ReadFileRecord(i, file);

    //printf("\n Record %d - Flags: %d\n\n", i, file->Flags);
    //printf("\nType: %s\n\n", file->Ntfs.Type);
    //printf("\nType: %s - Flags: %02x\n\n", file->Ntfs.Type, file->Flags);

    if (file->Ntfs.Type == 'ELIF' && (file->Flags == 1 || file->Flags == 3))
    {
      // Get, but Ignore Short Name 
      attr = FindAttribute(file, AttributeFileName, 0);
      if (attr == 0)
        continue;

      // Lets See if we have a Long File Name
      attr2 = FindAttributeII(file, AttributeFileName, 0);
      if (attr2 == 0)
      {
        UseName = 1;
        name = PFILENAME_ATTRIBUTE(Padd(attr, PRESIDENT_ATTRIBUTE(attr)->ValueOffset));

        Str_Len = int(name->NameLength);
        wcstombs(Str_Temp, name->Name, Str_Len);
        Str_Temp[Str_Len] = '\0'; // Null Terminate the String... Sigh...
      }
      else
      {
        UseName = 2;
        name2 = PFILENAME_ATTRIBUTE(Padd(attr2, PRESIDENT_ATTRIBUTE(attr2)->ValueOffset));

        Str_Len = int(name2->NameLength);
        wcstombs(Str_Temp, name2->Name, Str_Len);
        Str_Temp[Str_Len] = '\0'; // Null Terminate the String... Sigh...
      }


      // Lets Grab The SI Attribute for SI File Dates (Cre/Acc/Mod)
      attr3 = FindAttribute(file, AttributeStandardInformation, 0);
      if (attr3 != 0)
      {
        name3 = PSTANDARD_INFORMATION(Padd(attr3, PRESIDENT_ATTRIBUTE(attr3)->ValueOffset));
      }

      
      if (file->Flags == 1)
      {
        // Active File Entry 
        //wprintf(L"\nMFTFile: %u - %.*s (%u)\n", int(name2->DirectoryFileReferenceNumber), int(name2->NameLength), name2->Name, i);
        Max_Files++;

        if (UseName == 1)
        {
          if(attr3 == 0)
            dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileCreDate, FileAccDate, FileModDate, FileDateTyp) VALUES ('%ld', '%ld', '%q', '%llu', '%llu', '%llu', 'FN')\0", i, int(name->DirectoryFileReferenceNumber), Str_Temp, ULONGLONG(name->CreationTime), ULONGLONG(name->LastAccessTime), ULONGLONG(name->LastWriteTime));
          else
            dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileCreDate, FileAccDate, FileModDate, FileDateTyp) VALUES ('%ld', '%ld', '%q', '%llu', '%llu', '%llu', 'SI')\0", i, int(name->DirectoryFileReferenceNumber), Str_Temp, ULONGLONG(name3->CreationTime), ULONGLONG(name3->LastAccessTime), ULONGLONG(name3->LastWriteTime));
        }
        else
        {
          if (attr3 == 0)
            dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileCreDate, FileAccDate, FileModDate, FileDateTyp) VALUES ('%ld', '%ld', '%q', '%llu', '%llu', '%llu', 'FN')\0", i, int(name2->DirectoryFileReferenceNumber), Str_Temp, ULONGLONG(name2->CreationTime), ULONGLONG(name2->LastAccessTime), ULONGLONG(name2->LastWriteTime));
          else
            dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName, FileCreDate, FileAccDate, FileModDate, FileDateTyp) VALUES ('%ld', '%ld', '%q', '%llu', '%llu', '%llu', 'SI')\0", i, int(name2->DirectoryFileReferenceNumber), Str_Temp, ULONGLONG(name3->CreationTime), ULONGLONG(name3->LastAccessTime), ULONGLONG(name3->LastWriteTime));
        }
      }
      else
      {
        // Active Directory Entry
        //wprintf(L"\nMFTDirs: %u - %.*s (%u)\n", int(name2->DirectoryFileReferenceNumber), int(name2->NameLength), name2->Name, i);
        if(UseName == 1)
         dbMQuery = sqlite3_mprintf("INSERT INTO MFTDirs (MFTRecID, MFTPrvID, DirsName) VALUES ('%ld', '%ld', '%q')\0", i, int(name->DirectoryFileReferenceNumber), Str_Temp);
        else
         dbMQuery = sqlite3_mprintf("INSERT INTO MFTDirs (MFTRecID, MFTPrvID, DirsName) VALUES ('%ld', '%ld', '%q')\0", i, int(name2->DirectoryFileReferenceNumber), Str_Temp);
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
          printf("MFTError: Error Adding Entry to MFTDirs Table\n%s\n", errmsg);
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
  

  // Commit Before we build the Searchable Index
  dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);

  // Begin - To speed up performance
  dbMrc = sqlite3_exec(dbMFTHndl, "begin", 0, 0, &errmsg);

  Progress = 0;
  ProgUnit = Max_Files / 50;
  wprintf(L"\nFindActive() - Building Searchable Index...\nooooooooooooooooooooooooooooooooooooooooooooooooo\r");


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
      return ;
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
            strncpy(Full_Fname, (const char *) sqlite3_column_text(dbMFTStmt, dbi), 255);
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
        //else
        //if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FileCreDate", 11) == 0)
        //{
        //  memset(Text_CreDate, 0, 30);
        //  strncpy(Text_CreDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
        //}
        //else
        //if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FileAccDate", 11) == 0)
        //{
        //  memset(Text_AccDate, 0, 30);
        //  strncpy(Text_AccDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
        //}
        //else
        //if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FileModDate", 11) == 0)
        //{
        //  memset(Text_ModDate, 0, 30);
        //  strncpy(Text_ModDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
        //}
        //else
        //if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FileDateTyp", 11) == 0)
        //{
        //  memset(Text_DateTyp, 0, 5);
        //  strncpy(Text_DateTyp, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 2);
        //}
      }

      // Expand out the Full File Paths
      MoreDirs = 0;
      while(MoreDirs == 0)
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

                  // . is The Root (C:\)
                  if (_strnicmp(Ftmp_Fname, ".", 1) == 0)
                  {
                    strncpy(Ftmp_Fname, "C:\\\0\0", 4);
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
      //dbXQuery = sqlite3_mprintf("INSERT INTO FileNames (MFTRecID, FileName, FileCreDate, FileAccDate, FileModDate, FileDateTyp) VALUES ('%ld', '%q', '%q', '%q', '%q', '%q')\0", File_RecID, Full_Fname, Text_CreDate, Text_AccDate, Text_ModDate, Text_DateTyp);
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
          printf("MFTError: Error Adding Entry to FileNames Table\n%s\n", errmsg);
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

   

      //printf("FullFname: %s\n", Full_Fname);
      //getchar();



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
  wprintf(L"\nFindActive() - Building FileName Index...\n");
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
  
  


    
  //Test for 1000 recs
  //if (i > 1000)
  //{
  //  dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);
  //  sqlite3_close(dbMFTHndl);
  //  exit(0);
  //}
  // To see the very long output short, uncomment the following line
  // _getwch();

}


VOID FindDeleted()
{
  PATTRIBUTE attr = FindAttribute(MFT, AttributeBitmap, 0);
  PUCHAR bitmap = new UCHAR[AttributeLengthAllocated(attr)];
  ReadAttribute(attr, bitmap);
  ULONG n = AttributeLength(FindAttribute(MFT, AttributeData, 0)) / BytesPerFileRecord;
  wprintf(L"FindDeleted() - Finding the deleted files...\n");

  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
  for (ULONG i = 0; i < n; i++)
  {
    if (bitset(bitmap, i))
      continue;
    ReadFileRecord(i, file);
    if (file->Ntfs.Type == 'ELIF' && (file->Flags & 1) == 0)
    {
      attr = FindAttribute(file, AttributeFileName, 0);
      if (attr == 0)
        continue;
      PFILENAME_ATTRIBUTE name =
      PFILENAME_ATTRIBUTE(Padd(attr, PRESIDENT_ATTRIBUTE(attr)->ValueOffset));
      // * means the width/precision was supplied in the argument list
      // ws ~ wide character string
      wprintf(L"\n%10u %u %.*s\n-----\n\n", i, int(name->NameLength), int(name->NameLength), name->Name);
      // To see the very long output short, uncomment the following line
      // _getwch();
    }
  }
}


//VOID DumpData(ULONG index, CHAR* filename)
VOID DumpData(ULONG index, WCHAR* filename)
{
  PATTRIBUTE attr = NULL;
  HANDLE hFile = NULL;
  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
  ULONG n;
  
  memset(Str_Temp, 0, 1024);
  wcstombs(Str_Temp, filename, 1000);

  ReadFileRecord(index, file);

  //wprintf(L"Dumping the data...\n");
  printf("Dumping Raw Data to FileName: %s\n", Str_Temp);

  if (file->Ntfs.Type != 'ELIF')
    return;

  attr = FindAttribute(file, AttributeData, 0);
  if (attr == 0)
    return;

  PUCHAR buf = new UCHAR[AttributeLengthAllocated(attr)];

  ReadAttribute(attr, buf);

  //hFile = CreateFile((LPCWSTR)filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
  hFile = CreateFile((LPCSTR)Str_Temp, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    wprintf(L"CreateFile() failed, error %u\n", GetLastError());
    return;
  }

  if (WriteFile(hFile, buf, AttributeLength(attr), &n, 0) == 0)
  {
    wprintf(L"WriteFile() failed, error %u\n", GetLastError());
    return;
  }

  CloseHandle(hFile);

  delete[] buf;
}


VOID DumpDataII(ULONG index, CHAR* filename, FILETIME ToCreTime, FILETIME ToModTime, FILETIME ToAccTime)
{
  PATTRIBUTE attr = NULL;
  HANDLE hFile = NULL;
  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
  ULONG n;
  CHAR Tooo_Fname[2048] = "\0";
  int setOwner = 0;

  sprintf(Tooo_Fname, "C:\\AChoir\\Cache\\%s\0", filename);
  ReadFileRecord(index, file);

  //wprintf(L"Dumping the data...\n");
  printf("Dumping Raw Data to FileName: %s\n", Tooo_Fname);

  if (file->Ntfs.Type != 'ELIF')
    return;

  attr = FindAttribute(file, AttributeData, 0);
  if (attr == 0)
    return;

  PUCHAR buf = new UCHAR[AttributeLengthAllocated(attr)];

  ReadAttribute(attr, buf);

  hFile = CreateFile((LPCSTR)Tooo_Fname, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    wprintf(L"CreateFile() failed, error %u\n", GetLastError());
    return;
  }

  if (WriteFile(hFile, buf, AttributeLength(attr), &n, 0) == 0)
  {
    wprintf(L"WriteFile() failed, error %u\n", GetLastError());
    return;
  }


  //Set the File Times
  SetFileTime(hFile, &ToCreTime, &ToAccTime, &ToModTime);
  
  CloseHandle(hFile);

  /****************************************************************/
  /* Set the SID (Owner) of the new file same as the old file     */
  /****************************************************************/
  if (gotOwner == 1)
  {
    setOwner = SetFileSecurity(Tooo_Fname, OWNER_SECURITY_INFORMATION, SecDesc);

    if (setOwner)
     printf("File Owner was Set\n");
    else
     printf("Could NOT Set Target File Owner\n");
  }
  else
    printf("Could NOT Determine Source File Owner(Unknown)\n");
  
  delete[] buf;
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


/****************************************************************/
/* Elevate Priveleges of Access Token                           */
/****************************************************************/
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
  TOKEN_PRIVILEGES ToknPriv;
  LUID luid;

  if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
  {
    // printf("Err: LookupPrivilegeValue error: %u\n", GetLastError());
    return FALSE;
  }

  ToknPriv.PrivilegeCount = 1;
  ToknPriv.Privileges[0].Luid = luid;
  if (bEnablePrivilege)
    ToknPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  else
    ToknPriv.Privileges[0].Attributes = 0;

  // Enable the privilege or disable all privileges.
  if (!AdjustTokenPrivileges(hToken, FALSE, &ToknPriv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
  {
    // printf("Err: AdjustTokenPrivileges error: %u\n", GetLastError());
    return FALSE;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
  {
    // printf("Inf: Could Not Set Special Privilege: %s\n", lpszPrivilege);
    return FALSE;
  }

  return TRUE;
}


//int wmain(int argc, CHAR **argv)
int wmain(int argc, WCHAR **argv)
{
  // Default primary partition
  //WCHAR drive[] = L"\\\\.\\C:";

  CHAR drive[] = "\\\\.\\C:";
  ULONG n;

  char Full_Fname[2048] = "\0";
  int  Full_MFTID;
  int  SQL_MFT = 0;
  int  i;

  //SYSTEMTIME File_SysTime;
  //FILETIME File_Time, File_Local;
  ULONGLONG File_CreDate, File_AccDate, File_ModDate;
  FILETIME File_Create, File_Access, File_Modify;
  char Text_CreDate[30] = "\0";
  char Text_AccDate[30] = "\0";
  char Text_ModDate[30] = "\0";

  DWORD SecLen, LenSec;
  PSID pSidOwner = NULL;
  BOOL pFlag = FALSE;
  char SidString[256];

  HANDLE SecTokn;
  int PrivSet = 0;
  int PrivOwn = 0;
  int PrivSec = 0;
  int PrivBac = 0;
  int PrivRes = 0;



  // No argument supplied
  if (argc < 2)
  {
    wprintf(L"Usage:\n");
    wprintf(L"Find deleted files: %s <primary_partition>\n", argv[0]);
    wprintf(L"Read the file records: %s <primary_partition> <index> <file_name>\n", argv[0]);
    // Just exit
    exit(1);
  }


  // More code to stop the user from entering the non-primary partition
  // Read the user input
  drive[4] = *argv[1];


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

  printf("Privileges(%d):", PrivSet);

  if (PrivSet == 0)
   printf(" None");
  else
  {
    if (PrivOwn == 1)
     printf(" TakeOwnership");

    if (PrivSec == 1)
     printf(" Security");

    if (PrivBac == 1)
     printf(" Backup");

    if (PrivRes == 1)
     printf(" Restore");
  }
  printf("\n");


  // Get the handle to the primary partition/volume/physical disk
  hVolume = CreateFile(drive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
  if (hVolume == INVALID_HANDLE_VALUE)
  {
    wprintf(L"CreateFile() failed, error %u\n", GetLastError());
    exit(1);
  }


  // Reads data from the specified input/output (I/O) device - volume / physical disk
  if (ReadFile(hVolume, &bootb, sizeof bootb, &n, 0) == 0)
  {
    wprintf(L"ReadFile() failed, error %u\n", GetLastError());
    exit(1);
  }



  if (argc == 2)
  {
    MFT_Status = 0;

    //If the SQLite MFT is already there - Bypass the Index Creation
    if ((_access(MFTDBFile, 0)) != -1)
      SQL_MFT = 0;
    else
      SQL_MFT = 1;
    

    dbrc = sqlite3_open(MFTDBFile, &dbMFTHndl);
    if (dbrc != SQLITE_OK)
    {
      printf("Could Not Open MFT Working Database: %s\n", MFTDBFile);
      exit(4);
      return 4;
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
      //dbMQuery = sqlite3_mprintf("CREATE TABLE FileNames (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, FileName, FileCreDate INTEGER, FileAccDate INTEGER, FileModDate INTEGER)\0");
      //dbMQuery = sqlite3_mprintf("CREATE TABLE FileNames (MFTRecID INTEGER PRIMARY KEY, FileName, FileCreDate INTEGER, FileAccDate INTEGER, FileModDate INTEGER)\0");
      //dbMQuery = sqlite3_mprintf("CREATE TABLE FileNames (MFTRecID INTEGER PRIMARY KEY, FileName)\0");
      //dbMQuery = sqlite3_mprintf("CREATE TABLE FileNames (MFTRecID INTEGER PRIMARY KEY, FileName, FileCreDate, FileAccDate, FileModDate, FileDateTyp)\0");
      dbMQuery = sqlite3_mprintf("CREATE TABLE FileNames (MFTRecID INTEGER PRIMARY KEY, FullFileName)\0");
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
      //dbMQuery = sqlite3_mprintf("CREATE TABLE MFTFiles (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, MFTPrvID INTEGER, FileName)\0");
      //dbMQuery = sqlite3_mprintf("CREATE TABLE MFTFiles (MFTRecID INTEGER PRIMARY KEY, MFTPrvID INTEGER, FileName)\0");
      dbMQuery = sqlite3_mprintf("CREATE TABLE MFTFiles (MFTRecID INTEGER PRIMARY KEY, MFTPrvID INTEGER, FileName, FileCreDate, FileAccDate, FileModDate, FileDateTyp)\0");

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


      //dbMQuery = sqlite3_mprintf("CREATE TABLE MFTDirs (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, MFTPrvID INTEGER, DirsName)\0");
      dbMQuery = sqlite3_mprintf("CREATE TABLE MFTDirs (MFTRecID INTEGER PRIMARY KEY, MFTPrvID INTEGER, DirsName)\0");
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

      //Load MFT Info
      LoadMFT();

      // The primary partition supplied else
      // default C:\ will be used

      FindActive();


      // Lets do some Test Queries Against the SQLite MFT DB 
      dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);
    }
    else
      LoadMFT(); // SQLite Index exists, Just open the MFT

      

    /************************************************************/
    /* Show everything in Prefetch                              */
    /************************************************************/
    dbMQuery = sqlite3_mprintf("Select * FROM FileNames AS T1, MFTFiles AS T2 WHERE T1.FullFileName LIKE '%q' AND T1.MFTRecID=T2.MFTRecID\0", "C:\\Windows\\Prefetch\\%\0");

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
            if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FullFileName", 8) == 0)
            {
              if (sqlite3_column_text(dbMFTStmt, dbi) != NULL)
                strncpy(Full_Fname, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 2000);
            }
            else
            if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "MFTRecID", 8) == 0)
            {
              Full_MFTID = sqlite3_column_int(dbMFTStmt, dbi);
            }
            else
            if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FileCreDate", 11) == 0)
            {
              memset(Text_CreDate, 0, 30);
              strncpy(Text_CreDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
            }
            else
            if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FileAccDate", 11) == 0)
            {
              memset(Text_AccDate, 0, 30);
              strncpy(Text_AccDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
            }
            else
            if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "FileModDate", 11) == 0)
            {
              memset(Text_ModDate, 0, 30);
              strncpy(Text_ModDate, (const char *)sqlite3_column_text(dbMFTStmt, dbi), 25);
            }
          }

          for (i = strlen(Full_Fname); i > 0; i--)
          {
            if (Full_Fname[i] == '\\')
              break;
          }
          
          File_CreDate = atoll(Text_CreDate);
          File_AccDate = atoll(Text_AccDate);
          File_ModDate = atoll(Text_ModDate);

          printf("Raw Copying FileName: %s\nMFT Record: %d\n", Full_Fname+i+1, Full_MFTID);
          printf("   %s\n", Full_Fname);

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
          
          printf("Created: %s\n", Text_CreDate);
          printf("Modified: %s\n", Text_ModDate);
          printf("Accessed: %s\n", Text_AccDate);
          printf("SID: %s\n", SidString);

          DumpDataII(Full_MFTID, Full_Fname+i+1, File_Create, File_Modify, File_Access);

          if (SecDesc)
            free(SecDesc);

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
  }
  
  
  
  




  // FindDeleted();
  // Need to convert the recovered filename to long file name
  // Not implemented here. It is 8.3 file name format
  // The primary partition, index and file name to be recovered
  // are supplied

  if (argc == 4)
  {
    //Load MFT Info
    LoadMFT();

    //Physical Disk File Copy
    //DumpData(strtoul(argv[2], 0, 0), argv[3]);
    DumpData(wcstoul(argv[2], 0, 0), argv[3]);
  }

  CloseHandle(hVolume);



  return 0;
}
