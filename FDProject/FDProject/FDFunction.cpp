#include <Windows.h>
#include "FDFuntion.h"

struct FILE_INFO
{

};

BOOL CHEnableDebugPriority(VOID)
{
	HANDLE hTokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivileges;
	BOOL bFlag = FALSE;

	bFlag = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTokenHandle);

	if (!bFlag)
	{
		bFlag = FALSE;
	}
	else
	{
		bFlag = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &TokenPrivileges.Privileges[0].Luid);

		if (!bFlag)
		{
			bFlag = FALSE;
		}
		else
		{
			TokenPrivileges.PrivilegeCount = 1;
			TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			bFlag = AdjustTokenPrivileges(hTokenHandle, FALSE, &TokenPrivileges, 0, (PTOKEN_PRIVILEGES)NULL, 0);
		}
	}

	if (hTokenHandle != NULL)
	{
		CloseHandle(hTokenHandle);
	}

	return bFlag;
}

DWORD CHQueryFileNameByHandleThreadFunc(LPVOID pParam)
{	
	

	return 0;
}
