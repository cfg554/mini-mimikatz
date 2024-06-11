/*
 * 工具模块，不包含重要逻辑，仅包含十六进制打印二进制数组的功能
 * 无需修改
 */

#include "utils.h"
#include "stdio.h"

VOID HexdumpBytes(IN PBYTE pbPrintData, IN DWORD cbDataLen) {
    for (DWORD dwCount = 0; dwCount < cbDataLen; dwCount++) {
        printf("%02x ", pbPrintData[dwCount]);
        if ((dwCount + 1) % 16 == 0) {
            printf("| ");
            for (DWORD i = dwCount - 15; i <= dwCount; i++) {
                if (pbPrintData[i] >= 32 && pbPrintData[i] <= 126) {
                    printf("%c", pbPrintData[i]);
                }
                else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }

    if (cbDataLen % 16 != 0) {
        DWORD padding = 16 - (cbDataLen % 16);
        for (DWORD i = 0; i < padding; i++) {
            printf("   ");
        }
        printf("| ");
        for (DWORD i = cbDataLen - (cbDataLen % 16); i < cbDataLen; i++) {
            if (pbPrintData[i] >= 32 && pbPrintData[i] <= 126) {
                printf("%c", pbPrintData[i]);
            }
            else {
                printf(".");
            }
        }
        printf("\n");
    }

    puts("");
}

VOID HexdumpBytesPacked(IN PBYTE pbPrintData, IN DWORD cbDataLen) {
    for (DWORD dwCount = 0; dwCount < cbDataLen; dwCount++) {
        printf("%02x", pbPrintData[dwCount]);
    }
}
