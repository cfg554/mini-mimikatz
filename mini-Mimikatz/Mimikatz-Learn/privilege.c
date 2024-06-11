#include "privilege.h"
#include <stdio.h>

/*****************************************************
 *  �뽫���º�����д��������ʵ�ֶ�Ӧ�Ĺ���              *
 *    - EnableSeDebugPrivilege                       *
 *****************************************************/
/// �Ƽ�ʹ��API: OpenProcessToken() LookupPrivilegeValueW() AdjustTokenPrivileges()
BOOL EnableSeDebugPrivilege() {
    //
    // ~ 30 lines of code
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hToken;
    TOKEN_PRIVILEGES NewState;
    LUID luidPrivilegeLUID;

    // ��ȡ��������
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) || !LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luidPrivilegeLUID)){
        printf("SetPrivilege Error\n");
        return FALSE;
    }

    //���ú�Ȩ�ޣ����������ֵ
    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = luidPrivilegeLUID;
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    //��������Ȩ��
    if (!AdjustTokenPrivileges(hToken, FALSE, &NewState, NULL, NULL, NULL)) {
        printf("AdjustTokenPrivilege Error\n");
        return FALSE;
    }
    return TRUE;
}

/// Checks the corresponding Windows privilege and returns True or False.
BOOL CheckWindowsPrivilege(IN PWCHAR Privilege) {
    LUID luid;
    PRIVILEGE_SET privs = { 0 };
    HANDLE hProcess;
    HANDLE hToken;
    hProcess = GetCurrentProcess();
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
    if (!LookupPrivilegeValueW(NULL, Privilege, &luid)) return FALSE;
    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL bResult;
    PrivilegeCheck(hToken, &privs, &bResult);
    return bResult;
}

/// ����Administrator��SeDebugPrivilegeȨ��
VOID AdjustProcessPrivilege() {
    BOOL success = EnableSeDebugPrivilege();
    if (!success || !CheckWindowsPrivilege((WCHAR*)SE_DEBUG_NAME)) {
        printf("AdjustProcessPrivilege() not working ...\n");
        printf("Are you running as Admin ? ...\n");
        ExitProcess(-1);
    } else {
        printf("\n[+] AdjustProcessPrivilege() ok .\n\n");
    }
}