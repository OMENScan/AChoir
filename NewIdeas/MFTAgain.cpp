// MFTAgain.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

// Not using winioctl.h lol!
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "ntfs.h"
// Global variables
ULONG BytesPerFileRecord;
HANDLE hVolume;
BOOT_BLOCK bootb;
PFILE_RECORD_HEADER MFT;
// Template for padding
template <class T1, class T2> inline T1* Padd(T1* p, T2 n)
{
  return (T1*)((char *)p + n);
}
ULONG RunLength(PUCHAR run)
{
  wprintf(L"In RunLength()...\n");
  return (*run & 0xf) + ((*run >> 4) & 0xf) + 1;
}
LONGLONG RunLCN(PUCHAR run)
{
  LONG i = 0;
  UCHAR n1 = 0, n2 = 0;
  LONGLONG lcn = 0;
  wprintf(L"In RunLCN()...\n");
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
  wprintf(L"In RunCount()...\n");
  for (i = n; i > 0; i--)
    count = (count << 8) + run[i];
  return count;
}
BOOL FindRun(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, PULONGLONG lcn,
  PULONGLONG count)
{
  PUCHAR run = NULL;
  *lcn = 0;
  ULONGLONG base = attr->LowVcn;
  wprintf(L"In FindRun()...\n");
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
PATTRIBUTE FindAttribute(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, PWSTR
  name)
{
  PATTRIBUTE attr = NULL;
  wprintf(L"FindAttribute() - Finding attributes...\n");
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
VOID FixupUpdateSequenceArray(PFILE_RECORD_HEADER file)
{
  ULONG i = 0;
  PUSHORT usa = PUSHORT(Padd(file, file->Ntfs.UsaOffset));
  PUSHORT sector = PUSHORT(file);
  wprintf(L"In FixupUpdateSequenceArray()...\n");
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
  wprintf(L"ReadSector() - Reading the sector...\n");
  wprintf(L"Sector: %lu\n", sector);
  offset.QuadPart = sector * bootb.BytesPerSector;
  overlap.Offset = offset.LowPart;
  overlap.OffsetHigh = offset.HighPart;
  ReadFile(hVolume, buffer, count * bootb.BytesPerSector, &n, &overlap);
}
VOID ReadLCN(ULONGLONG lcn, ULONG count, PVOID buffer)
{
  wprintf(L"\nReadLCN() - Reading the LCN, LCN: 0X%.8X\n", lcn);
  ReadSector(lcn * bootb.SectorsPerCluster, count * bootb.SectorsPerCluster,
    buffer);
}
// Non resident attributes
VOID ReadExternalAttribute(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, ULONG
  count, PVOID buffer)
{
  ULONGLONG lcn, runcount;
  ULONG readcount, left;
  PUCHAR bytes = PUCHAR(buffer);
  wprintf(L"ReadExternalAttribute() - Reading the Non resident attributes...\n");
    for (left = count; left > 0; left -= readcount)
    {
      FindRun(attr, vcn, &lcn, &runcount);
      readcount = ULONG(min(runcount, left));
      ULONG n = readcount * bootb.BytesPerSector *
        bootb.SectorsPerCluster;
      if (lcn == 0)
        memset(bytes, 0, n);
      else
      {
        ReadLCN(lcn, readcount, bytes);
        wprintf(L"LCN: 0X%.8X\n", lcn);
      }
      vcn += readcount;
      bytes += n;
    }
}
ULONG AttributeLength(PATTRIBUTE attr)
{
  wprintf(L"In AttributeLength()...\n");
  return attr->Nonresident == FALSE ?
    PRESIDENT_ATTRIBUTE(attr)->ValueLength :
    ULONG(PNONRESIDENT_ATTRIBUTE(attr)->DataSize);
}
ULONG AttributeLengthAllocated(PATTRIBUTE attr)
{
  wprintf(L"\nIn AttributeLengthAllocated()...\n");
  return attr->Nonresident == FALSE ?
    PRESIDENT_ATTRIBUTE(attr)->ValueLength :
    ULONG(PNONRESIDENT_ATTRIBUTE(attr)->AllocatedSize);
}
VOID ReadAttribute(PATTRIBUTE attr, PVOID buffer)
{
  PRESIDENT_ATTRIBUTE rattr = NULL;
  PNONRESIDENT_ATTRIBUTE nattr = NULL;
  wprintf(L"ReadAttribute() - Reading the attributes...\n");
  if (attr->Nonresident == FALSE)
  {
    wprintf(L"Resident attribute...\n");
    rattr = PRESIDENT_ATTRIBUTE(attr);
    memcpy(buffer, Padd(rattr, rattr->ValueOffset), rattr->ValueLength);
  }
  else
  {
    wprintf(L"Non-resident attribute...\n");
    nattr = PNONRESIDENT_ATTRIBUTE(attr);
    ReadExternalAttribute(nattr, 0, ULONG(nattr->HighVcn) + 1, buffer);
  }
}
VOID ReadVCN(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, ULONGLONG vcn, ULONG
  count, PVOID buffer)
{
  PATTRIBUTE attrlist = NULL;
  PNONRESIDENT_ATTRIBUTE attr = PNONRESIDENT_ATTRIBUTE(FindAttribute(file,
    type, 0));
  wprintf(L"In ReadVCN()...\n");
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
  wprintf(L"ReadFileRecord() - Reading the file records..\n");
  if (clusters > 0x80)
    clusters = 1;
  PUCHAR p = new UCHAR[bootb.BytesPerSector* bootb.SectorsPerCluster *
    clusters];
  ULONGLONG vcn = ULONGLONG(index) *
    BytesPerFileRecord / bootb.BytesPerSector / bootb.SectorsPerCluster;
  ReadVCN(MFT, AttributeData, vcn, clusters, p);
  LONG m = (bootb.SectorsPerCluster *
    bootb.BytesPerSector / BytesPerFileRecord) - 1;
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
  wprintf(L"bootb.ClustersPerFileRecord = %u\n",
    bootb.ClustersPerFileRecord);
  wprintf(L"bootb.ClustersPerIndexBlock = %u\n",
    bootb.ClustersPerIndexBlock);
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
  wprintf(L"bootb.VolumeSerialNumber = 0X%.8X%.8X\n\n",
    bootb.VolumeSerialNumber.HighPart, bootb.VolumeSerialNumber.HighPart);
  MFT = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
  ReadSector((bootb.MftStartLcn)*(bootb.SectorsPerCluster),
    (BytesPerFileRecord) / (bootb.BytesPerSector), MFT);
  FixupUpdateSequenceArray(MFT);
}
BOOL bitset(PUCHAR bitmap, ULONG i)
{
  return (bitmap[i >> 3] & (1 << (i & 7))) != 0;
}
VOID FindDeleted()
{
  PATTRIBUTE attr = FindAttribute(MFT, AttributeBitmap, 0);
  PUCHAR bitmap = new UCHAR[AttributeLengthAllocated(attr)];
  ReadAttribute(attr, bitmap);
  ULONG n = AttributeLength(FindAttribute(MFT, AttributeData,
    0)) / BytesPerFileRecord;
  wprintf(L"FindDeleted() - Finding the deleted files...\n");
  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new
    UCHAR[BytesPerFileRecord]);
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
        wprintf(L"\n%10u %u %.*s\n\n", i, int(name->NameLength),
          int(name->NameLength), name->Name);
      // To see the very long output short, uncomment the following line
        // _getwch();
    }
  }
}
VOID DumpData(ULONG index, WCHAR* filename)
{
  PATTRIBUTE attr = NULL;
  HANDLE hFile = NULL;
  PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new
    UCHAR[BytesPerFileRecord]);
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
  hFile = CreateFile((LPCWSTR)filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
    0, 0);
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
  WCHAR drive[] = L"\\\\.\\C:";
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
  hVolume = CreateFile(
    drive,
    GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    0,
    OPEN_EXISTING,
    0,
    0);
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
  LoadMFT();
  // The primary partition supplied else
  // default C:\ will be used
  if (argc == 2)
    FindDeleted();
  // Need to convert the recovered filename to long file name
  // Not implemented here. It is 8.3 file name format
  // The primary partition, index and file name to be recovered
  // are supplied
  if (argc == 4)
    DumpData(wcstoul(argv[2], 0, 0), argv[3]);
  CloseHandle(hVolume);
  return 0;
}