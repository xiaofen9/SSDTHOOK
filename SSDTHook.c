#include "SSDTHook.h"
/*
一个SSDT框架： 
实现了基础功能
	去页面保护
	恢复页面保护
	备份原有SSDT表
	安装钩子
	恢复原有表
*/

//=====================================================================================//
//Name: VOID DisableWriteProtect()												       //
//                                                                                     //
//Descripion: 用来去掉内存的可写属性，从而实现内存只读						           //
//            				                            						       //
//=====================================================================================//
VOID DisableWriteProtect(ULONG oldAttr)
{
	_asm
	{
		mov eax, oldAttr
		mov cr0, eax
		sti;
	}
}


//=====================================================================================//
//Name: VOID EnableWriteProtect()												       //
//                                                                                     //
//Descripion: 用来去掉内存的只读保护，从而实现可以写内存					           //
//            				                            						       //
//=====================================================================================//
VOID EnableWriteProtect(PULONG pOldAttr)
{
	ULONG uAttr; 

	_asm 
	{ 
		cli;
		mov  eax, cr0; 
		mov  uAttr, eax; 
		and  eax, 0FFFEFFFFh; // CR0 16 BIT = 0 
		mov  cr0, eax; 
	}; 

	//保存原有的 CRO 属性 
	*pOldAttr = uAttr; 
}


//=====================================================================================//
//Name: VOID BackupSysServicesTable()											       //
//                                                                                     //
//Descripion: 用来备份 SSDT 中原有服务的地址，因为我们在解除 Hook 时需要还原 SSDT 中原有地址 //
//            				                            						       //
//=====================================================================================//
VOID BackupSysServicesTable()
{
	ULONG i;

	for(i = 0; (i < KeServiceDescriptorTable->ntoskrnl.NumberOfService) && (i < MAX_SYSTEM_SERVICE_NUMBER); i++)
	{
		oldSysServiceAddr[i] = KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[i];
		//oldSysServiceAddr[i] = *(PULONG)((ULONG)KeServiceDescriptorTable->ntoskrnl.ServiceTableBase + 4 * i);

		KdPrint(("\nBackupSysServicesTable - Function Information { Number: 0x%04X , Address: %08X}", i, oldSysServiceAddr[i]));
	}
}


//=====================================================================================//
//Name: NTSTATUS InstallSysServiceHook()										       //
//                                                                                     //
//Descripion: 实现 Hook 的安装，主要是在 SSDT 中用 newService 来替换掉 oldService	   //
//            				                            						       //
//=====================================================================================//
NTSTATUS InstallSysServiceHook(ULONG oldService, ULONG newService)
{
	ULONG uOldAttr = 0;

	EnableWriteProtect(&uOldAttr);

	SYSCALL_FUNCTION(oldService) = newService;
	//KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[SYSCALL_INDEX(oldService)] = newService;

	DisableWriteProtect(uOldAttr);

	return STATUS_SUCCESS;
}


//=====================================================================================//
//Name: NTSTATUS UnInstallSysServiceHook()										       //
//                                                                                     //
//Descripion: 实现 Hook 的解除，主要是在 SSDT 中用备份下的服务地址来替换掉 oldService  //
//            				                            						       //
//=====================================================================================//
NTSTATUS UnInstallSysServiceHook(ULONG oldService)
{
	ULONG uOldAttr = 0;

	EnableWriteProtect(&uOldAttr);

	SYSCALL_FUNCTION(oldService) = oldSysServiceAddr[SYSCALL_INDEX(oldService)];
	//KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[SYSCALL_INDEX(oldService)] = oldSysServiceAddr[SYSCALL_INDEX(oldService)];

	DisableWriteProtect(uOldAttr);

	return STATUS_SUCCESS;
}
