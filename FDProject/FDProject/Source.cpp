//#include <Windows.h>
//
//	//����������DebugȨ��
//	BOOL MyEnableDebugPriority(VOID)
//{
//	HANDLE hTokenHandle = NULL;
//	TOKEN_PRIVILEGES TokenPrivileges;
//	BOOL bFlag = FALSE;
//
//	//��������������
//	bFlag = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTokenHandle);
//	if (!bFlag)
//	{
//		bFlag = FALSE;
//	}
//	else
//	{
//		//��ѯDebugȨ��
//		bFlag = LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &TokenPrivileges.Privileges[0].Luid);
//		if (!bFlag)
//		{
//			bFlag = FALSE;
//		}
//		else
//		{
//			TokenPrivileges.PrivilegeCount = 1;
//			TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //��������Ȩ��
//			bFlag = AdjustTokenPrivileges(hTokenHandle, FALSE, &TokenPrivileges, 0, (PTOKEN_PRIVILEGES)NULL, 0);  //����Ȩ��
//		}
//	}
//
//	if (hTokenHandle != NULL)
//	{
//		CloseHandle(hTokenHandle);
//	}
//
//	return bFlag;
//}
//DWORD WINAPI MyQueryFileNameByHandleThreadFunc(LPVOID pParam)
//{
//	FILE_INFO *pFileInfo = (FILE_INFO*)pParam;
//
//	WCHAR wcVolume[3] = { 0 };
//
//	NTSTATUS MyNtStatus;
//	IO_STATUS_BLOCK IoStatus;
//	UCHAR szBuff[0x1000];
//	RtlZeroMemory(szBuff, sizeof(szBuff));
//	FILE_NAME_INFORMATION *pFileNameInformation = (FILE_NAME_INFORMATION*)szBuff;
//
//	MyNtStatus = NtQueryInformationFile(pFileInfo->hFileHandle, &IoStatus, pFileNameInformation,
//		sizeof(FILE_INFO) - sizeof(HANDLE) - sizeof(BOOL), FileNameInformationClass);
//
//	if (NT_SUCCESS(MyNtStatus))
//	{
//		if (pFileNameInformation->FileNameLength != 0)
//		{
//			pFileInfo->bFlag = TRUE;
//			pFileInfo->FileNameInfo.FileNameLength = pFileNameInformation->FileNameLength;
//			if (MyGetVolumeNameByHandle(pFileInfo->hFileHandle, wcVolume))// �õ��̷�
//			{
//				RtlZeroMemory(pFileInfo->FileNameInfo.FileName, sizeof(pFileInfo->FileNameInfo.FileName));
//
//				pFileInfo->FileNameInfo.FileName[0] = wcVolume[0];
//				pFileInfo->FileNameInfo.FileName[1] = wcVolume[1];
//
//				wcsncpy(&pFileInfo->FileNameInfo.FileName[2],
//					pFileNameInformation->FileName,
//					pFileNameInformation->FileNameLength);
//
//				pFileInfo->FileNameInfo.FileName[2 + pFileNameInformation->FileNameLength - 1] = 0;
//			}
//
//		}
//	}
//
//
//	return 0;
//}
//
//
////��ȡ��ǰ����ϵͳ���ļ���� ��objectֵ
////���������NtQuerySystemInformation
//UCHAR MyGetOsFileHandleObject(VOID)
//{
//	UCHAR ucResult = 0;
//	DWORD dwSize = 100;
//	DWORD dwNeedSize = 0;
//	NTSTATUS MyNtStatus;
//	DWORD dwCurProcessId = GetCurrentProcessId();
//	DWORD dwIndex = 0;
//
//	HANDLE hTempFile = CreateFileW(_T("C:\\boot.ini"), 0, 0, NULL, OPEN_EXISTING, 0, 0);
//
//	SYSTEM_HANDLE_INFORMATION* pSystemsHandleInformation = (SYSTEM_HANDLE_INFORMATION*)VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
//
//	if (NULL == pSystemsHandleInformation)
//	{
//		return 0;
//	}
//
//	MyNtStatus = NtQuerySystemInformation(SystemHandleInformation, pSystemsHandleInformation, dwSize, &dwNeedSize);
//
//	if (STATUS_INFO_LENGTH_MISMATCH == MyNtStatus)
//	{
//		if (0 == dwNeedSize)
//		{
//			ucResult = 0;
//			goto MyErrorExit;
//		}
//		else
//		{
//			VirtualFree(pSystemsHandleInformation, 0, MEM_RELEASE);
//			pSystemsHandleInformation = (SYSTEM_HANDLE_INFORMATION*)VirtualAlloc(NULL, dwNeedSize, MEM_COMMIT, PAGE_READWRITE);
//
//			if (NULL == pSystemsHandleInformation)
//			{
//				ucResult = 0;
//				goto MyErrorExit;
//			}
//		}
//	}
//
//	MyNtStatus = NtQuerySystemInformation(SystemHandleInformation, pSystemsHandleInformation, dwNeedSize, NULL);
//
//	if (!NT_SUCCESS(MyNtStatus))
//	{
//		goto MyErrorExit;
//	}
//	for (dwIndex = 0; dwIndex<pSystemsHandleInformation->Count; dwIndex++)
//	{
//		if ((dwCurProcessId == pSystemsHandleInformation->Handles[dwIndex].ProcessID) &&
//			(hTempFile == (HANDLE)pSystemsHandleInformation->Handles[dwIndex].HandleNumber))
//		{
//			ucResult = (UCHAR)pSystemsHandleInformation->Handles[dwIndex].HandleType; //�õ��������
//			OutputDebugStringW(_T("\n�õ��������\n"));
//			break;
//		}
//
//	}
//
//
//MyErrorExit:
//
//	if (pSystemsHandleInformation != NULL)
//	{
//		VirtualFree(pSystemsHandleInformation, 0, MEM_RELEASE);
//	}
//
//	if (hTempFile != INVALID_HANDLE_VALUE)
//	{
//		CloseHandle(hTempFile);
//	}
//
//	return ucResult;
//}
////����ϵͳ��ǰ�����ļ������ÿ�õ�һ�����Ͳ���������Ӧ���ļ���
//DWORD WINAPI MyLookupHandleThreadFunc(LPVOID pParam)
//{
//	LOOKUP_INFO * pLockorInfo = (LOOKUP_INFO*)pParam;
//
//	DWORD dwSize = 100;
//	DWORD dwNeedSize = 0;
//	NTSTATUS MyNtStatus;
//	DWORD dwCurProcessId = GetCurrentProcessId();
//	DWORD dwIndex = 0;
//	BOOL bRemoteFlag = FALSE;
//	HANDLE hRemoteProcess = NULL;
//	HANDLE hCurProcess = GetCurrentProcess();
//
//	BOOL bDupliFlag = FALSE;
//
//
//	HANDLE hTureHandle = NULL;
//
//	SYSTEM_HANDLE_INFORMATION* pSystemsHandleInformation = (SYSTEM_HANDLE_INFORMATION*)VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
//
//	if (NULL == pSystemsHandleInformation)
//	{
//		pLockorInfo->bFlag = FALSE;
//		if (pSystemsHandleInformation != NULL)
//		{
//			VirtualFree(pSystemsHandleInformation, 0, MEM_RELEASE);
//		}
//		if (hCurProcess != NULL)
//		{
//			CloseHandle(hCurProcess);
//		}
//		return -1;
//	}
//
//	MyNtStatus = NtQuerySystemInformation(SystemHandleInformation, pSystemsHandleInformation, dwSize, &dwNeedSize);
//
//	if (STATUS_INFO_LENGTH_MISMATCH == MyNtStatus)
//	{
//		if (0 == dwNeedSize)
//		{
//			pLockorInfo->bFlag = FALSE;
//			if (pSystemsHandleInformation != NULL)
//			{
//				VirtualFree(pSystemsHandleInformation, 0, MEM_RELEASE);
//			}
//			if (hCurProcess != NULL)
//			{
//				CloseHandle(hCurProcess);
//			}
//			return -1;
//		}
//
//		VirtualFree(pSystemsHandleInformation, 0, MEM_RELEASE);
//		pSystemsHandleInformation = (SYSTEM_HANDLE_INFORMATION*)VirtualAlloc(NULL, dwNeedSize, MEM_COMMIT, PAGE_READWRITE);
//
//		if (NULL == pSystemsHandleInformation)
//		{
//			pLockorInfo->bFlag = FALSE;
//			if (pSystemsHandleInformation != NULL)
//			{
//				VirtualFree(pSystemsHandleInformation, 0, MEM_RELEASE);
//			}
//			if (hCurProcess != NULL)
//			{
//				CloseHandle(hCurProcess);
//			}
//			return -1;
//		}
//
//	}
//
//	MyNtStatus = NtQuerySystemInformation(SystemHandleInformation, pSystemsHandleInformation, dwNeedSize, NULL);
//
//	if (!NT_SUCCESS(MyNtStatus))
//	{
//		pLockorInfo->bFlag = FALSE;
//		if (pSystemsHandleInformation != NULL)
//		{
//			VirtualFree(pSystemsHandleInformation, 0, MEM_RELEASE);
//		}
//		if (hCurProcess != NULL)
//		{
//			CloseHandle(hCurProcess);
//		}
//		return -1;
//	}
//
//
//
//
//	for (dwIndex = 0; dwIndex<pSystemsHandleInformation->Count; dwIndex++)
//	{
//		if (4 == pSystemsHandleInformation->Handles[dwIndex].ProcessID)    //system�ǲ���
//		{
//			continue;
//		}
//
//		//�����ļ������ֱ��54
//		if (pLockorInfo->ucOSFileHandleType != pSystemsHandleInformation->Handles[dwIndex].HandleType)
//		{
//			continue;
//		}
//
//		if (dwCurProcessId == pSystemsHandleInformation->Handles[dwIndex].ProcessID)
//		{
//			bRemoteFlag = FALSE;
//			hTureHandle = (HANDLE)pSystemsHandleInformation->Handles[dwIndex].HandleNumber;
//		}
//		else
//		{
//			bRemoteFlag = TRUE;
//			hRemoteProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pSystemsHandleInformation->Handles[dwIndex].ProcessID);
//			if (hRemoteProcess != NULL)
//			{
//
//				bDupliFlag = DuplicateHandle(hRemoteProcess, (HANDLE)pSystemsHandleInformation->Handles[dwIndex].HandleNumber,
//					hCurProcess, &hTureHandle, 0, FALSE, DUPLICATE_SAME_ACCESS); //������ͬȨ�޵�handle
//
//				if (!bDupliFlag)
//				{
//					hTureHandle = NULL;
//				}
//			}
//
//			if (hRemoteProcess != NULL)
//			{
//				CloseHandle(hRemoteProcess);
//			}
//		}
//
//		if (hTureHandle != NULL)
//		{
//
//			//�����ļ������ȡ�ļ�·��
//			if (MyGetFileNameByHandle(hTureHandle, pLockorInfo->szFileName))
//			{
//
//				pLockorInfo->bFlag = TRUE;
//				pLockorInfo->dwLockProcessId = pSystemsHandleInformation->Handles[dwIndex].ProcessID;
//				pLockorInfo->wLockHandle = pSystemsHandleInformation->Handles[dwIndex].HandleNumber;
//
//				MyCloseRemoteHandle(pSystemsHandleInformation->Handles[dwIndex].ProcessID,
//					(HANDLE)pSystemsHandleInformation->Handles[dwIndex].HandleNumber);
//
//			}
//
//			//ÿһ��ʹ�ú�����
//			if (bRemoteFlag)
//			{
//				CloseHandle(hTureHandle);
//			}
//		}
//
//
//	}
//
//	if (pSystemsHandleInformation != NULL)
//	{
//		VirtualFree(pSystemsHandleInformation, 0, MEM_RELEASE);
//	}
//	if (hCurProcess != NULL)
//	{
//		CloseHandle(hCurProcess);
//	}
//
//	return 0;
//}
//
////�����ļ������ȡ�ļ�·�����߳�
//BOOL MyGetFileNameByHandle(__in HANDLE hFileHandle, __out WCHAR *szFileName)
//{
//	BOOL bFindFlag = FALSE;
//	FILE_INFO FileInfo;
//	RtlZeroMemory(&FileInfo, sizeof(FileInfo));
//	FileInfo.bFlag = FALSE;
//	FileInfo.hFileHandle = hFileHandle;
//
//	HANDLE hQueryThread = CreateThread(NULL, 0, MyQueryFileNameByHandleThreadFunc, &FileInfo, 0, NULL);
//
//	if (WAIT_TIMEOUT == WaitForSingleObject(hQueryThread, 100))
//	{
//		TerminateThread(hQueryThread, 2);
//	}
//
//	if (FileInfo.bFlag)
//	{
//		if (0 == wcsicmp(szFileName, FileInfo.FileNameInfo.FileName))
//		{
//			bFindFlag = TRUE;
//		}
//	}
//
//	if (hQueryThread != NULL)
//	{
//		CloseHandle(hQueryThread);
//	}
//
//	return bFindFlag;
//}
//
//DWORD WINAPI MyQueryFileNameByHandleThreadFunc(LPVOID pParam)
//{
//	FILE_INFO *pFileInfo = (FILE_INFO*)pParam;
//
//	WCHAR wcVolume[3] = { 0 };
//
//	NTSTATUS MyNtStatus;
//	IO_STATUS_BLOCK IoStatus;
//	UCHAR szBuff[0x1000];
//	RtlZeroMemory(szBuff, sizeof(szBuff));
//	FILE_NAME_INFORMATION *pFileNameInformation = (FILE_NAME_INFORMATION*)szBuff;
//
//	MyNtStatus = NtQueryInformationFile(pFileInfo->hFileHandle, &IoStatus, pFileNameInformation,
//		sizeof(FILE_INFO) - sizeof(HANDLE) - sizeof(BOOL), FileNameInformationClass);
//
//	if (NT_SUCCESS(MyNtStatus))
//	{
//		if (pFileNameInformation->FileNameLength != 0)
//		{
//			pFileInfo->bFlag = TRUE;
//			pFileInfo->FileNameInfo.FileNameLength = pFileNameInformation->FileNameLength;
//			if (MyGetVolumeNameByHandle(pFileInfo->hFileHandle, wcVolume))// �õ��̷�
//			{
//				RtlZeroMemory(pFileInfo->FileNameInfo.FileName, sizeof(pFileInfo->FileNameInfo.FileName));
//
//				pFileInfo->FileNameInfo.FileName[0] = wcVolume[0];
//				pFileInfo->FileNameInfo.FileName[1] = wcVolume[1];
//
//				wcsncpy(&pFileInfo->FileNameInfo.FileName[2],
//					pFileNameInformation->FileName,
//					pFileNameInformation->FileNameLength);
//
//				pFileInfo->FileNameInfo.FileName[2 + pFileNameInformation->FileNameLength - 1] = 0;
//			}
//
//		}
//	}
//
//
//	return 0;
//}
//
//void GetOSVolumeSerialInfo(void)
//{
//	RtlZeroMemory(&VolumeInfo, sizeof(VolumeInfo));
//
//	WCHAR szVolumeName[5] = { 0 };
//	WCHAR Drive = 'A';
//	DWORD dwDiskMask = GetLogicalDrives();
//	int nIndex = 0;
//	for (nIndex = 0; nIndex<26; nIndex++)
//	{
//		if (((1 << nIndex) & dwDiskMask) != 0)
//		{
//			Drive = nIndex + 'A';
//			wsprintfW(szVolumeName, _T("%c:\\"), Drive);
//			wsprintfW(VolumeInfo[nIndex].szVolumeName, _T("%c:"), Drive);
//			GetVolumeInformation(szVolumeName, NULL, 0, &VolumeInfo[nIndex].dwVolumeSerial, 0, 0, 0, 0);
//		}
//	}
//}void GetOSVolumeSerialInfo(void)
//{
//	RtlZeroMemory(&VolumeInfo, sizeof(VolumeInfo));
//
//	WCHAR szVolumeName[5] = { 0 };
//	WCHAR Drive = 'A';
//	DWORD dwDiskMask = GetLogicalDrives();
//	int nIndex = 0;
//	for (nIndex = 0; nIndex<26; nIndex++)
//	{
//		if (((1 << nIndex) & dwDiskMask) != 0)
//		{
//			Drive = nIndex + 'A';
//			wsprintfW(szVolumeName, _T("%c:\\"), Drive);
//			wsprintfW(VolumeInfo[nIndex].szVolumeName, _T("%c:"), Drive);
//			GetVolumeInformation(szVolumeName, NULL, 0, &VolumeInfo[nIndex].dwVolumeSerial, 0, 0, 0, 0);
//		}
//	}
//}
//
//BOOL MyGetVolumeNameByHandle(__in HANDLE hFile, __out WCHAR *szVolume)
//{
//	DWORD dwIndex = 0;
//	BY_HANDLE_FILE_INFORMATION stHandleFileInfo;
//	RtlZeroMemory(&stHandleFileInfo, sizeof(stHandleFileInfo));
//
//	GetFileInformationByHandle(hFile, &stHandleFileInfo);
//	for (dwIndex = 0; dwIndex<26; dwIndex++)
//	{
//		if (stHandleFileInfo.dwVolumeSerialNumber != 0)
//		{
//			if (stHandleFileInfo.dwVolumeSerialNumber == VolumeInfo[dwIndex].dwVolumeSerial)
//			{
//				wcscpy(szVolume, VolumeInfo[dwIndex].szVolumeName);
//				return TRUE;
//			}
//		}
//	}
//	return FALSE;
//}
//
////����pid=dwProcessId�е�hRemoteHandle���
//BOOL MyCloseRemoteHandle(__in DWORD dwProcessId, __in HANDLE hRemoteHandle)
//{
//	HANDLE hExecutHandle = NULL;
//	BOOL bFlag = FALSE;
//	HANDLE hProcess = NULL;
//	HMODULE hKernel32Module = NULL;
//
//	hProcess = OpenProcess(
//		PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
//		FALSE, dwProcessId);
//
//	if (NULL == hProcess)
//	{
//		bFlag = FALSE;
//		goto MyErrorExit;
//	}
//
//	hKernel32Module = LoadLibrary(_T("kernel32.dll"));
//
//	hExecutHandle = CreateRemoteThread(hProcess, 0, 0,
//		(DWORD(__stdcall *)(void *))GetProcAddress(hKernel32Module, "CloseHandle"),
//		hRemoteHandle, 0, NULL);
//
//	if (NULL == hExecutHandle)
//	{
//		bFlag = FALSE;
//		goto MyErrorExit;
//	}
//
//	if (WaitForSingleObject(hExecutHandle, 2000) == WAIT_OBJECT_0)
//	{
//		bFlag = TRUE;
//		goto MyErrorExit;
//	}
//	else
//	{
//		bFlag = FALSE;
//		goto MyErrorExit;
//	}
//
//
//
//MyErrorExit:
//
//	if (hExecutHandle != NULL)
//	{
//		CloseHandle(hExecutHandle);
//	}
//
//	if (hProcess != NULL)
//	{
//		CloseHandle(hProcess);
//	}
//
//	if (hKernel32Module != NULL)
//	{
//		FreeLibrary(hKernel32Module);
//	}
//	return bFlag;
//}
//
////����PID��ȡ������
//BOOL MyGetProcessNameByPID(DWORD dwProcessId, WCHAR *szProcessName)
//{
//	BOOL bReturnFlag = FALSE;
//	PROCESSENTRY32* pProcessInfo = new PROCESSENTRY32;
//
//	pProcessInfo->dwSize = sizeof(PROCESSENTRY32);
//
//	HANDLE MyHandProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//
//	BOOL bFlag = Process32First(MyHandProcessSnap, pProcessInfo);
//
//	while (bFlag)
//	{
//		if (dwProcessId == pProcessInfo->th32ProcessID)
//		{
//			wcscpy(szProcessName, pProcessInfo->szExeFile);
//			bReturnFlag = TRUE;
//			break;
//		}
//		bFlag = Process32Next(MyHandProcessSnap, pProcessInfo);
//	}
//
//	if (pProcessInfo != NULL)
//	{
//		delete pProcessInfo;
//		pProcessInfo = NULL;
//	}
//
//	if (MyHandProcessSnap != NULL)
//	{
//		CloseHandle(MyHandProcessSnap);
//	}
//	return bReturnFlag;
//}
//
////����PID��ȡ����·��
//BOOL MyGetProcessPathByPID(DWORD dwProcessId, WCHAR *szProcessPath)
//{
//	HANDLE hModule;
//	MODULEENTRY32* pMoudleInfo = new MODULEENTRY32;
//	pMoudleInfo->dwSize = sizeof(MODULEENTRY32);
//	hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
//	Module32First(hModule, pMoudleInfo);
//
//	wcscpy(szProcessPath, pMoudleInfo->szExePath);
//
//	if (pMoudleInfo != NULL)
//	{
//		delete pMoudleInfo;
//		pMoudleInfo = NULL;
//	}
//
//	if (hModule != NULL)
//	{
//		CloseHandle(hModule);
//	}
//	return TRUE;
//}