//#include <iostream>
//
//int main(int argc, char* argv[])
//{
//
//
//	return 0;
//}

#pragma once

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <atlbase.h>
#include <shlwapi.h>

#include <vector>
#include <map>
using namespace std;

#include <string>
typedef std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>> tstring;

#include <winternl.h>

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#define NT_SUCCESS(status)					(status == (NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH			((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW				((NTSTATUS)0x80000005L)
#define SystemHandleInformation				((SYSTEM_INFORMATION_CLASS)16)

// NTQUERYOBJECT
typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
	WCHAR NameBuffer[1];
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef enum class C_OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} COBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI *NTQUERYOBJECT)(
	_In_opt_ HANDLE Handle,
	_In_ COBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_opt_ PVOID ObjectInformation,
	_In_ ULONG ObjectInformationLength,
	_Out_opt_ PULONG ReturnLength);

// NTQUERYSYSTEMINFORMATION
typedef struct _SYSTEM_HANDLE {
	DWORD dwProcessId;
	BYTE bObjectType;
	BYTE bFlags;
	WORD wValue;
	PVOID pAddress;
	DWORD GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	DWORD dwCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(WINAPI *NTQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

//
// NtQueryInformationFile
//
#define FileNameInformation					((FILE_INFORMATION_CLASS)9)

// typedef struct _FILE_NAME_INFORMATION {
// 	ULONG FileNameLength;
// 	WCHAR FileName[1];
// } FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef NTSTATUS(WINAPI *NTQUERYINFORMATIONFILE)(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

// typedef struct _CLIENT_ID {
// 	HANDLE UniqueProcess;
// 	HANDLE UniqueThread;
// } CLIENT_ID, *PCLIENT_ID;

// ncScopedHandle
class ncScopedHandle
{
	ncScopedHandle(const ncScopedHandle&);
	ncScopedHandle& operator=(const ncScopedHandle&);
public:
	ncScopedHandle(HANDLE handle)
		: _handle(handle)
	{
	}

	~ncScopedHandle()
	{
		if (_handle != NULL) {
			CloseHandle(_handle);
		}
	}

	operator HANDLE() const
	{
		return _handle;
	}

	PHANDLE  operator& ()
	{
		return &_handle;
	}

	void operator=(HANDLE handle)
	{
		if (_handle != NULL) {
			CloseHandle(_handle);
		}
		_handle = handle;
	}

private:
	HANDLE _handle;
};

// ncFileHandle
struct ncFileHandle
{
	SYSTEM_HANDLE	_handle;
	tstring			_filePath;
	tstring			_path;

	ncFileHandle(SYSTEM_HANDLE handle, const tstring& filePath, const tstring& path)
		: _handle(handle)
		, _filePath(filePath)
		, _path(path)
	{
	}
};

// GetDeviceDriveMap 获取驱动器路径表
void GetDeviceDriveMap(std::map<tstring, tstring>& mapDeviceDrive)
{
	TCHAR szDrives[512];
	if (!GetLogicalDriveStrings(_countof(szDrives) - 1, szDrives)) {
		return;
	}

	TCHAR* lpDrives = szDrives;
	TCHAR szDevice[MAX_PATH];
	TCHAR szDrive[3] = _T(" :");
	do {
		*szDrive = *lpDrives;

		if (QueryDosDevice(szDrive, szDevice, MAX_PATH)) {
			mapDeviceDrive[szDevice] = szDrive;
		}
		while (*lpDrives++);
	} while (*lpDrives);
}

// DevicePathToDrivePath 设备路径转换为驱动器路径
BOOL DevicePathToDrivePath(tstring& path)
{
	static std::map<tstring, tstring> mapDeviceDrive;

	if (mapDeviceDrive.empty()) {
		GetDeviceDriveMap(mapDeviceDrive);
	}

	for (std::map<tstring, tstring>::const_iterator it = mapDeviceDrive.begin(); it != mapDeviceDrive.end(); ++it) {
		size_t nLength = it->first.length();
		if (_tcsnicmp(it->first.c_str(), path.c_str(), nLength) == 0) {
			path.replace(0, nLength, it->second);
			return TRUE;
		}
	}

	return FALSE;
}

// GetHandlePath
// 获取对应文件句柄的文件路径
BOOL GetHandlePath(HANDLE handle, tstring& path)
{
	static NTQUERYOBJECT fpNtQueryObject =
		(NTQUERYOBJECT)GetProcAddress(GetModuleHandle(_T("ntdll")), "NtQueryObject");

	if (fpNtQueryObject == NULL) {
		return FALSE;
	}

	DWORD dwLength = 0;
	OBJECT_NAME_INFORMATION info;
	// 请求句柄指向的文件的相关信息
	NTSTATUS status = fpNtQueryObject(handle, C_OBJECT_INFORMATION_CLASS::ObjectNameInformation, &info, sizeof(info), &dwLength);
	if (status != STATUS_BUFFER_OVERFLOW) {
		return FALSE;
	}

	POBJECT_NAME_INFORMATION pInfo = (POBJECT_NAME_INFORMATION)malloc(dwLength);
	while (true) {
		status = fpNtQueryObject(handle, C_OBJECT_INFORMATION_CLASS::ObjectNameInformation, pInfo, dwLength, &dwLength);
		if (status != STATUS_BUFFER_OVERFLOW) {
			break;
		}
		pInfo = (POBJECT_NAME_INFORMATION)realloc(pInfo, dwLength);
	}

	BOOL bRes = FALSE;
	if (NT_SUCCESS(status)) {
		path = pInfo->Name.Buffer;
		// 请求的文件路径是计算机内部使用的路径，需要转换为常用的用户认识的路径表示形式
		bRes = DevicePathToDrivePath(path);
	}
	free(pInfo);
	return bRes;
}

// GetSystemHandleInfo
/**
* 获取系统句柄信息
*
* @return 返回所有句柄信息的链表
*/
PSYSTEM_HANDLE_INFORMATION GetSystemHandleInfo()
{
	// 从ntdll中获取NtQuerySystemInformation函数接口
	// 获取系统的指定的信息
	static NTQUERYSYSTEMINFORMATION fpNtQuerySystemInformation =
		(NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(_T("ntdll")), "NtQuerySystemInformation");

	if (fpNtQuerySystemInformation == NULL) {
		return NULL;
	}

	DWORD dwLength = 0;
	SYSTEM_HANDLE_INFORMATION shi;
	NTSTATUS status = fpNtQuerySystemInformation(SystemHandleInformation, &shi, sizeof(shi), &dwLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		return NULL;
	}

	PSYSTEM_HANDLE_INFORMATION pshi = (PSYSTEM_HANDLE_INFORMATION)malloc(dwLength);
	while (true) {
		status = fpNtQuerySystemInformation(SystemHandleInformation, pshi, dwLength, &dwLength);
		if (status != STATUS_INFO_LENGTH_MISMATCH) {
			break;
		}
		pshi = (PSYSTEM_HANDLE_INFORMATION)realloc(pshi, dwLength);
	}

	if (!NT_SUCCESS(status)) {
		free(pshi);
		pshi = NULL;
	}

	return pshi;
}

//
// 检测指定句柄是否可能导致NtQueryObject卡死：
//     1.注意必须使用NtQueryInformationFile而不是NtQueryObject进行检测，否则可能导致WinXP系统
//       下进程死锁而无法结束。
//
void CheckBlockThreadFunc(void* param)
{
	static NTQUERYINFORMATIONFILE fpNtQueryInformationFile =
		(NTQUERYINFORMATIONFILE)GetProcAddress(GetModuleHandle(_T("ntdll")), "NtQueryInformationFile");

	if (fpNtQueryInformationFile != NULL) {
		BYTE buf[1024];
		IO_STATUS_BLOCK ioStatus;
		fpNtQueryInformationFile((HANDLE)param, &ioStatus, buf, 1024, FileNameInformation);
	}
}

// IsBlockingHandle
// 如果非管道占用，那么这个线程是可以马上返回的，如果是管道占用，这个线程会卡死
BOOL IsBlockingHandle(HANDLE handle)
{
	HANDLE hThread = (HANDLE)_beginthread(CheckBlockThreadFunc, 0, (void*)handle);

	if (WaitForSingleObject(hThread, 100) != WAIT_TIMEOUT) {
		return FALSE;
	}

	TerminateThread(hThread, 0);
	return TRUE;
}

// FindFileHandle
/**
* 寻找指定文件/文件夹下所有文件的占用信息
*
* @param LPCTSTR lpName 文件或文件夹路径
* @param vector<ncFileHandle>& handles 存储所有占用信息缓存
*/
BOOL FindFileHandle(LPCTSTR lpName, vector<ncFileHandle>& handles)
{
	handles.clear();

	if (lpName == NULL) {
		return FALSE;
	}

	// 打开“NUL”文件以便后续获取文件句柄类型值。
	ncScopedHandle hTempFile = CreateFile(_T("NUL"), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
	if (hTempFile == NULL) {
		return FALSE;
	}

	// 获取当前系统中所有的句柄信息。
	PSYSTEM_HANDLE_INFORMATION pshi = GetSystemHandleInfo();
	if (pshi == NULL) {
		return FALSE;
	}

	// 查询当前系统的文件句柄类型值。
	BYTE nFileType = 0;
	DWORD dwCrtPid = GetCurrentProcessId();
	for (DWORD i = 0; i < pshi->dwCount; ++i) {
		// 如果当前句柄等于当前进程id并且这个句柄类型属于文件句柄类型
		// 将当前系统的文件句柄类型存储起来，并退出循环
		// 因为当前进程打开了NUL文件，所有获取句柄信息的时候，会把这个打开信息存储在当前
		// 系统的句柄信息中，根据这个特性，获取文件句柄的类型
		if (pshi->Handles[i].dwProcessId == dwCrtPid && hTempFile == (HANDLE)pshi->Handles[i].wValue) {
			nFileType = pshi->Handles[i].bObjectType;
			break;
		}
	}

	HANDLE hCrtProc = GetCurrentProcess();
	for (DWORD i = 0; i < pshi->dwCount; ++i) {
		// 过滤掉非文件类型的句柄。
		if (pshi->Handles[i].bObjectType != nFileType) {
			continue;
		}

		// 将上述句柄复制到当前进程中。
		ncScopedHandle handle = NULL;
		ncScopedHandle hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pshi->Handles[i].dwProcessId);
		if (hProc == NULL || !DuplicateHandle(hProc, (HANDLE)pshi->Handles[i].wValue, hCrtProc, &handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
			continue;
		}

		// 过滤掉会导致NtQueryObject卡死的句柄（如管道等）。
		if (IsBlockingHandle(handle)) {
			continue;
		}

		// 获取句柄对应的文件路径并进行匹配检查。
		tstring filePath;
		if (GetHandlePath(handle, filePath) && filePath.find(lpName) != tstring::npos) {
			// 打开占用进程句柄，获取占用进程可执行文件的路径
			ncScopedHandle hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pshi->Handles[i].dwProcessId);

			TCHAR szProcName[MAX_PATH];
			GetProcessImageFileName(hProcess, szProcName, MAX_PATH);
			tstring path(szProcName);
			DevicePathToDrivePath(path);
			ncFileHandle fh(pshi->Handles[i], filePath, path);
			handles.push_back(fh);
		}
	}

	free(pshi);
	return TRUE;
}

// BOOL CloseHandleEx (HANDLE handle, DWORD dwPid)
// {
// 	if (GetCurrentProcessId () == dwPid)
// 		return CloseHandle (handle);
// 
// 	ncScopedHandle hProcess = OpenProcess (PROCESS_DUP_HANDLE, FALSE, dwPid);
// 	if (hProcess == NULL)
// 		return FALSE;
// 
// 	return DuplicateHandle (hProcess, handle, GetCurrentProcess (), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
// }

// main
int _tmain(int argc, _TCHAR* argv[])
{
	tstring path(_T("H:\\CloudMusic\\"));
	vector<ncFileHandle> vecHandles;
	if (!FindFileHandle(path.c_str(), vecHandles)) {
		return -1;
	}

	return 0;
}