// MFTAgain.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

// Not using winioctl.h lol!
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "ntfs.h"
#include "sqlite3.h"

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
      if (name != 0 && wcslen(name) == attr->NameLength &&
        _wcsicmp(name,
          PWSTR(Padd(attr, attr->NameOffset))) == 0)
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
        if (name != 0 && wcslen(name) == attr->NameLength &&
          _wcsicmp(name,
            PWSTR(Padd(attr, attr->NameOffset))) == 0)
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
  PUCHAR bitmap = new UCHAR[AttributeLengthAllocated(attr)];

  PFILENAME_ATTRIBUTE name;
  PFILENAME_ATTRIBUTE name2;

  char Full_Fname[2048] = "\0";
  char Ftmp_Fname[2048] = "\0";
  int Str_Len, Max_Files;
  int Progress, ProgUnit;
  int File_RecNum, Dir_PrevNum;
  int MoreDirs, UseName;

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


      if (file->Flags == 1)
      {
        // Active File Entry 
        //wprintf(L"\nMFTFile: %u - %.*s (%u)\n", int(name2->DirectoryFileReferenceNumber), int(name2->NameLength), name2->Name, i);
        Max_Files++;

        if(UseName == 1)
         dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName) VALUES ('%ld', '%ld', '%q')\0", i, int(name->DirectoryFileReferenceNumber), Str_Temp);
        else
         dbMQuery = sqlite3_mprintf("INSERT INTO MFTFiles (MFTRecID, MFTPrvID, FileName) VALUES ('%ld', '%ld', '%q')\0", i, int(name2->DirectoryFileReferenceNumber), Str_Temp);
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

        if (SpinLock > 5)
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
        }
        else
        if (_strnicmp(sqlite3_column_name(dbMFTStmt, dbi), "MFTPrvID", 8) == 0)
        {
          Dir_PrevNum = sqlite3_column_int(dbMFTStmt, dbi);
        }
      }








      MoreDirs = 0;
      while(MoreDirs == 0)
      {


        MoreDirs = 1; //Assume we will Exit out
        printf("Select * from MFTDirs WHERE MFTRecID = '%ld'\n", Dir_PrevNum);



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
              MoreDirs = 0; //Lets See if we have another Directory
              dbMaxCol = sqlite3_column_count(dbXMFTStmt);

              memset(Ftmp_Fname, 0, 260);
              for (dbXi = 0; dbXi < dbMaxCol; dbXi++)
              {
                if (_strnicmp(sqlite3_column_name(dbXMFTStmt, dbXi), "DirsName", 8) == 0)
                {
                  if (sqlite3_column_text(dbXMFTStmt, dbXi) != NULL)
                    strncpy(Ftmp_Fname, (const char *)sqlite3_column_text(dbXMFTStmt, dbXi), 255);



                  printf("Got Subdir: %s\n", Ftmp_Fname);





                  strcat(Ftmp_Fname, "\\\0\0");
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
            }
          }

          /*****************************************************************/
          /* Check if we are stuck in a loop.                              */
          /*****************************************************************/
          if (dbXrc != SQLITE_ROW)
          {
            SpinLock++;

            if (SpinLock > 5)
            {
              break;
            }
          }
        }

        sqlite3_finalize(dbXMFTStmt);
        sqlite3_free(dbXQuery);
      }





      printf("FullFname: %s\n", Full_Fname);
      getchar();











    }


    /*****************************************************************/
    /* Check if we are stuck in a loop.                              */
    /*****************************************************************/
    if (dbrc != SQLITE_ROW)
    {
      SpinLock++;
      if (SpinLock > 5)
      {
        break;
      }
    }
  }
  sqlite3_finalize(dbMFTStmt);


















      
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


VOID DumpData(ULONG index, WCHAR* filename)
{
  PATTRIBUTE attr = NULL;
  HANDLE hFile = NULL;
  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
  ULONG n;
  ReadFileRecord(index, file);
  wprintf(L"Dumping the data...\n");
  if (file->Ntfs.Type != 'ELIF')
    return;
  attr = FindAttribute(file, AttributeData, 0);
  if (attr == 0)
    return;
  PUCHAR buf = new UCHAR[AttributeLengthAllocated(attr)];
  ReadAttribute(attr, buf);
  //hFile = CreateFile((LPCWSTR)filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
  hFile = CreateFile((LPCSTR)filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
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


int wmain(int argc, WCHAR **argv)
{
  // Default primary partition
  //WCHAR drive[] = L"\\\\.\\C:";
  CHAR drive[] = "\\\\.\\C:";
  ULONG n;

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

  MFT_Status = 0;
  dbrc = sqlite3_open(MFTDBFile, &dbMFTHndl);
  if (dbrc != SQLITE_OK)
  {
    printf("Could Not Open MFT Working Database: %s\n", MFTDBFile);

    exit(0);
    return 0;
  }



  // Create SQLite DB
  dbrc = sqlite3_open(MFTDBFile, &dbMFTHndl);
  if (dbrc != SQLITE_OK)
  {
    printf("Could Not Create MFT Index Database: %s\n", MFTDBFile);

    exit(4);
    return 4;
  }

  // Make SQLite DB access as fast as possible
  dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA cache_size=4000", NULL, NULL, &errmsg);
  dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA synchronous=NORMAL", NULL, NULL, &errmsg);
  dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA journal_mode=MEMORY", NULL, NULL, &errmsg);
  dbrc = sqlite3_exec(dbMFTHndl, "PRAGMA temp_store=MEMORY", NULL, NULL, &errmsg);

  dbMrc = sqlite3_exec(dbMFTHndl, "begin", 0, 0, &errmsg);


  SpinLock = 0;
  dbMQuery = sqlite3_mprintf("CREATE TABLE FileNames (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, FileName, FileCreDate INTEGER, FileAccDate INTEGER, FileModDate INTEGER)\0");
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

    if (SpinLock > 5)
      break;
  }
  sqlite3_free(dbMQuery);


  SpinLock = 0;
  dbMQuery = sqlite3_mprintf("CREATE TABLE MFTFiles (RecID INTEGER PRIMARY KEY AUTOINCREMENT, MFTRecID INTEGER, MFTPrvID INTEGER, FileName)\0");
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

    if (SpinLock > 5)
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
      break;
    }
    else
      Sleep(100); // In windows.h

    /*****************************************************************/
    /* Check if we are stuck in a loop.                              */
    /*****************************************************************/
    SpinLock++;

    if (SpinLock > 5)
      break;
  }
  sqlite3_free(dbMQuery);


  LoadMFT();

  // The primary partition supplied else
  // default C:\ will be used

  if (argc == 2)
    FindActive();

  // FindDeleted();
  // Need to convert the recovered filename to long file name
  // Not implemented here. It is 8.3 file name format
  // The primary partition, index and file name to be recovered
  // are supplied

  if (argc == 4)
    DumpData(wcstoul(argv[2], 0, 0), argv[3]);


  CloseHandle(hVolume);

  dbrc = sqlite3_exec(dbMFTHndl, "commit", 0, 0, &errmsg);
  sqlite3_close(dbMFTHndl);

  return 0;
}
