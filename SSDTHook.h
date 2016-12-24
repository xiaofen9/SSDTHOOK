#ifndef __SSDT_HOOK_H__
#define __SSDT_HOOK_H__


#ifdef __cplusplus
extern "C" 
{
#endif

#include <ntddk.h>

#ifdef __cplusplus
}
#endif


//定义 SSDT(系统服务描述表) 中服务个数的最大数目
//这里定义为 1024 个，实际上在 XP SP3 是 0x0128 个
#define MAX_SYSTEM_SERVICE_NUMBER 1024


//=====================================================================================//
//Name: KSYSTEM_SERVICE_TABLE 和 KSERVICE_TABLE_DESCRIPTOR					           //
//                                                                                     //
//Descripion: 用来定义 SSDT 结构												  	       //
//            				                            						       //
//=====================================================================================//
typedef struct _KSYSTEM_SERVICE_TABLE
{
	PULONG  ServiceTableBase;					// SSDT (System Service Dispatch Table)的基地址
	PULONG  ServiceCounterTableBase;			// 用于 checked builds, 包含 SSDT 中每个服务被调用的次数
	ULONG   NumberOfService;					// 服务函数的个数, NumberOfService * 4 就是整个地址表的大小
	ULONG   ParamTableBase;						// SSPT(System Service Parameter Table)的基地址

} KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;


typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
	KSYSTEM_SERVICE_TABLE   ntoskrnl;			// ntoskrnl.exe 的服务函数
	KSYSTEM_SERVICE_TABLE   win32k;				// win32k.sys 的服务函数(GDI32.dll/User32.dll 的内核支持)
	KSYSTEM_SERVICE_TABLE   notUsed1;
	KSYSTEM_SERVICE_TABLE   notUsed2;

} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;


//导出由 ntoskrnl.exe 所导出的 SSDT
extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;


//根据 Zw_ServiceFunction 获取 Zw_ServiceFunction 在 SSDT 中所对应的服务的索引号
#define SYSCALL_INDEX(ServiceFunction) (*(PULONG)((PUCHAR)ServiceFunction + 1))


//根据 Zw_ServiceFunction 来获得服务在 SSDT 中的索引号，
//然后再通过该索引号来获取 Nt_ServiceFunction的地址
#define SYSCALL_FUNCTION(ServiceFunction) KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[SYSCALL_INDEX(ServiceFunction)]


//用来保存 SSDT 中所有的旧的服务函数的地址
ULONG oldSysServiceAddr[MAX_SYSTEM_SERVICE_NUMBER];

//禁止写入保护，也就是恢复到只读
VOID DisableWriteProtect(ULONG oldAttr);

//允许写入保护，也就是设置为可写
VOID EnableWriteProtect(PULONG pOldAttr);

//备份 SSDT 中所有系统服务的地址
VOID BackupSysServicesTable();

//安装 Hook
NTSTATUS InstallSysServiceHook(ULONG oldService, ULONG newService);

//解除 Hook
NTSTATUS UnInstallSysServiceHook(ULONG oldService);


#endif