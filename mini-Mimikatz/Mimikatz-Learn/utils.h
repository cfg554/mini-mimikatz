#pragma once

#include <Windows.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define NT_NOT_SUCCESS(Status)		(!NT_SUCCESS(Status))
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

VOID HexdumpBytes(IN PBYTE pbPrintData, IN DWORD cbDataLen);
VOID HexdumpBytesPacked(IN PBYTE pbPrintData, IN DWORD cbDataLen);