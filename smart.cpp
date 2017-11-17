
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Types *********************************************************************/
typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR2
{
	PWSTR pwszDllName;
	DWORD dwDllFlags;
	PVOID pvDllAddress;
	PVOID pvDllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR2, *PRTL_VERIFIER_DLL_DESCRIPTOR2;

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR2
{
	DWORD dwLength;
	PVOID pvProviderDlls;
	PVOID pvProviderDllLoadCallback;
	PVOID pvProviderDllUnloadCallback;
	PWSTR pwszVerifierImage;
	DWORD dwVerifierFlags;
	DWORD dwVerifierDebug;
	PVOID pvRtlpGetStackTraceAddress;
	PVOID pvRtlpDebugPageHeapCreate;
	PVOID pvRtlpDebugPageHeapDestroy;
	PVOID pvProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR2, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR2;

typedef struct _RTL_VERIFIER_MINILOADATTACH_PROVIDER_DESCRIPTOR2
{
	DWORD dwLength;
	DWORD dwReserved;
	DWORD dwReserved1;
	DWORD dwReserved2;
	DWORD dwReserved3;
	DWORD dwReserved4;
	DWORD dwReserved5;
	DWORD dwReserved6;
	PDWORD pdwAVrfDphGlobalFlags;
	PVOID pvAVrfpHeapTable;
	PRTL_VERIFIER_PROVIDER_DESCRIPTOR2 ptAVrfpProvider;
	CHAR szReserved7[0x18];
} RTL_VERIFIER_MINILOADATTACH_PROVIDER_DESCRIPTOR2, *PRTL_VERIFIER_MINILOADATTACH_PROVIDER_DESCRIPTOR2;

/* Global Variables **********************************************************/
RTL_VERIFIER_DLL_DESCRIPTOR2 atDLLs[] = { { 0 } };
RTL_VERIFIER_PROVIDER_DESCRIPTOR2 tVpd = { sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR2), atDLLs };

/* Function Definitions ******************************************************/
BOOL Verifier(IN PVOID pvReserved)
{

	/* Validates the parameters */
	if (NULL == pvReserved)
     return 0;

	/* Sets the reserved parameter */
	*((PRTL_VERIFIER_PROVIDER_DESCRIPTOR2 *)pvReserved) = &tVpd;
	return 1;

}

