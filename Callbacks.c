#include "Driver.h"

#include <ntddk.h>


VOID KernelAPC(PVOID Context, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4)
{
	ExFreePool(Context);
}

VOID UserAPC(PVOID Context, PVOID sysarg1, PVOID sysarg2)
{
	// (LOAD_LIB)(Context->LoadLibrary_Func)(Context->DllName);
}

VOID UserAPC_end()
{
	
}


ULONG CalcApcSize()
{
	return ((ULONG_PTR) UserAPC_end - (ULONG_PTR) UserAPC);
}

/// <summary>
/// Called when a thread has been created.
/// </summary>
/// <param name="ProcessId">The process identifier.</param>
/// <param name="ThreadId">The thread identifier.</param>
/// <param name="Create">Whether the thread is created or deleted.</param>
VOID CreateThreadNotifyRoutineCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	if (Create == FALSE)
	{
		return; // We don't want dying threads.
	}

	NTSTATUS Status		= STATUS_SUCCESS;
	PEPROCESS Process	= NULL;
	PETHREAD  Thread	= NULL;
	wchar_t DllPath[]   = L"Razer Synapse is loaded !";
	SIZE_T DllPathLen	= sizeof(DllPath);
	PVOID RegionBase;
	SIZE_T RegionLen	= sizeof(DllPath);;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		//DbgPrintEx(0, 0, "[WGS] Failed to lookup the process.\n");
		Status = STATUS_UNSUCCESSFUL;
		return;
	}

	if (!NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &Thread)))
	{
		//DbgPrintEx(0, 0, "[WGS] Failed to lookup the thread.\n");
		Status = STATUS_UNSUCCESSFUL;
		return;
	}


	if (*((unsigned char *) Thread + 0x4a) == 0x01)
	{
		DbgPrintEx(0, 0, "[WGS] Thread is in alerted state, possibly targetable.\n");
	}

	return;

	BOOLEAN isWow64		= TRUE;
	PKAPC APC			= (PKAPC) ExAllocatePool(NonPagedPool, sizeof(KAPC));
	PKAPC APC2			= (PKAPC) ExAllocatePool(NonPagedPool, sizeof(KAPC));
	PAPC_CONTEXT Context= NULL;
	PVOID UserAPC_mem	= NULL;
	ULONG csize			= sizeof(APC_CONTEXT);
	ULONG apcsize		= CalcApcSize();

	KeStackAttachProcess(PsGetCurrentProcess(), (PKAPC_STATE) APC);

	ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*) &Context, NULL, &csize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*) &UserAPC_mem, NULL, &apcsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*) &RegionBase, NULL, &RegionLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*) &RegionBase, NULL, &RegionLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	KeUnstackDetachProcess((PKAPC_STATE) APC);

	KeInitializeApc(APC2, (PKTHREAD) Thread, 0, (PKKERNEL_ROUTINE) KernelAPC, NULL, (PKNORMAL_ROUTINE) UserAPC_mem, UserMode, Context);
	KeInsertQueueApc(APC2, 0, NULL, 0);
}

/// <summary>
/// Called when a image has been loaded into a user-mode process.
/// </summary>
/// <param name="FullImageName">Full name of the image.</param>
/// <param name="ProcessId">The process identifier.</param>
/// <param name="ImageInfo">The image information.</param>
PLOAD_IMAGE_NOTIFY_ROUTINE LoadImageNotifyRoutineCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{

}

void unturned()
{
	INJECT_INFO InjectInfo;
	HANDLE hFile;
	WCHAR *ProgramLogFile = L"\\??\\C:\\somefile.log";

	LARGE_INTEGER AllocationSize;
	UNICODE_STRING LogFileName;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES ObjectAttributes;

	NTSTATUS Status;
	
	//
	// Open the Log File for writing.
	//
	RtlInitUnicodeString(&LogFileName, ProgramLogFile);
	InitializeObjectAttributes(
		&ObjectAttributes,
		&LogFileName,
		OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_OPENIF,
		NULL,
		NULL
	);
	AllocationSize.QuadPart = 64 * 1024;
	hFile = ZwCreateFile(
		&hFile,
		GENERIC_ALL | SYNCHRONIZE | FILE_ANY_ACCESS,
		&ObjectAttributes,
		&IoStatusBlock,
		&AllocationSize,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
		FILE_SUPERSEDE,
		FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT |
		FILE_SEQUENTIAL_ONLY | FILE_NON_DIRECTORY_FILE,
		NULL,
		0
	);
	wcscpy(InjectInfo.DllName, hFile);
}

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\SandWichDriver"), SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\SandWichDriver");

ULONG ApcStateOffset; // Offset to the ApcState structure
PLDR_LOAD_DLL LdrLoadDll; // LdrLoadDll address

void Unload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("DLL injection driver unloaded.");

	IoDeleteSymbolicLink(&SymbolicLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

void NTAPI KernelRoutine(PKAPC apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	ExFreePool(apc);
}

void NTAPI InjectDllApc(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	PKINJECT inject = (PKINJECT)NormalContext;

	inject->LdrLoadDll(NULL, NULL, &inject->DllName, &inject->DllBase);
	inject->Executed = TRUE;
}

BOOLEAN InjectDll(PINJECT_INFO InjectInfo)
{
	PEPROCESS Process;
	PETHREAD Thread;

	PKINJECT mem;
	ULONG size;

	PKAPC_STATE ApcState;
	PKAPC apc;

	PVOID buffer;
	PSYSTEM_PROCESS_INFO pSpi;

	LARGE_INTEGER delay;

	buffer = ExAllocatePool(NonPagedPool, 1024 * 1024); // Allocate memory for the system information

	if (!buffer)
	{
		DbgPrint("Error: Unable to allocate memory for the process thread list.");
		return FALSE;
	}

	// Get the process thread list

	if (!NT_SUCCESS(ZwQuerySystemInformation(5, buffer, 1024 * 1024, NULL)))
	{
		DbgPrint("Error: Unable to query process thread list.");

		ExFreePool(buffer);
		return FALSE;
	}

	pSpi = (PSYSTEM_PROCESS_INFO)buffer;

	// Find a target thread

	while (pSpi->NextEntryOffset)
	{
		if (pSpi->UniqueProcessId == InjectInfo->ProcessId)
		{
			DbgPrint("Target thread found. TID: %d", pSpi->Threads[0].ClientId.UniqueThread);
			break;
		}

		pSpi = (PSYSTEM_PROCESS_INFO)((PUCHAR)pSpi + pSpi->NextEntryOffset);
	}

	// Reference the target process

	if (!NT_SUCCESS(PsLookupProcessByProcessId(InjectInfo->ProcessId, &Process)))
	{
		DbgPrint("Error: Unable to reference the target process.");

		ExFreePool(buffer);
		return FALSE;
	}

	DbgPrint("Process name: %s", PsGetProcessImageFileName(Process));
	DbgPrint("EPROCESS address: %#x", Process);

	// Reference the target thread

	if (!NT_SUCCESS(PsLookupThreadByThreadId(pSpi->Threads[0].ClientId.UniqueThread, &Thread)))
	{
		DbgPrint("Error: Unable to reference the target thread.");
		ObDereferenceObject(Process); // Dereference the target process

		ExFreePool(buffer); // Free the allocated memory
		return FALSE;
	}

	DbgPrint("ETHREAD address: %#x", Thread);

	ExFreePool(buffer); // Free the allocated memory
	KeAttachProcess(Process); // Attach to target process's address space

	mem = NULL;
	size = 4096;

	// Allocate memory in the target process

	if (!NT_SUCCESS(ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&mem, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
	{
		DbgPrint("Error: Unable to allocate memory in the target process.");
		KeDetachProcess(); // Detach from target process's address space

		ObDereferenceObject(Process); // Dereference the target process
		ObDereferenceObject(Thread); // Dereference the target thread

		return FALSE;
	}

	DbgPrint("Memory allocated at %#x", mem);

	mem->LdrLoadDll = LdrLoadDll; // Write the address of LdrLoadDll to target process
	wcscpy(mem->Buffer, InjectInfo->DllName); // Write the DLL name to target process

	RtlInitUnicodeString(&mem->DllName, mem->Buffer); // Initialize the UNICODE_STRING structure
	ApcState = (PKAPC_STATE)((PUCHAR)Thread + ApcStateOffset); // Calculate the address of the ApcState structure

	ApcState->UserApcPending = TRUE; // Force the target thread to execute APC

	memcpy((PKINJECT)(mem + 1), InjectDllApc, (ULONG)KernelRoutine - (ULONG)InjectDllApc); // Copy the APC code to target process
	DbgPrint("APC code address: %#x", (PKINJECT)(mem + 1));

	apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC)); // Allocate the APC object

	if (!apc)
	{
		DbgPrint("Error: Unable to allocate the APC object.");
		size = 0;

		ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&mem, &size, MEM_RELEASE);  // Free the allocated memory
		KeDetachProcess(); // Detach from target process's address space

		ObDereferenceObject(Process); // Dereference the target process
		ObDereferenceObject(Thread); // Dereference the target thread

		return FALSE;
	}

	KeInitializeApc(apc, Thread, OriginalApcEnvironment, KernelRoutine, NULL, (PKNORMAL_ROUTINE)((PKINJECT)mem + 1), UserMode, mem); // Initialize the APC
	DbgPrint("Inserting APC to target thread");

	// Insert the APC to the target thread

	if (!KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT))
	{
		DbgPrint("Error: Unable to insert APC to target thread.");
		size = 0;

		ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&mem, &size, MEM_RELEASE); // Free the allocated memory
		KeDetachProcess(); // Detach from target process's address space

		ObDereferenceObject(Process); // Dereference the target process
		ObDereferenceObject(Thread); // Dereference the target thread

		ExFreePool(apc); // Free the APC object
		return FALSE;
	}

	delay.QuadPart = -100 * 10000;

	while (!mem->Executed)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &delay); // Wait for the injection to complete
	}

	if (!mem->DllBase)
	{
		DbgPrint("Error: Unable to inject DLL into target process.");
		size = 0;

		ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&mem, &size, MEM_RELEASE);
		KeDetachProcess();

		ObDereferenceObject(Process);
		ObDereferenceObject(Thread);

		return FALSE;
	}

	DbgPrint("DLL injected at %#x", mem->DllBase);
	size = 0;

	ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&mem, &size, MEM_RELEASE); // Free the allocated memory
	KeDetachProcess(); // Detach from target process's address space

	ObDereferenceObject(Process); // Dereference the target process
	ObDereferenceObject(Thread);  // Dereference the target thread

	return TRUE;
}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	PIO_STACK_LOCATION io;
	PINJECT_INFO InjectInfo;

	NTSTATUS status;

	io = IoGetCurrentIrpStackLocation(irp);
	irp->IoStatus.Information = 0;

	switch (io->MajorFunction)
	{
	case IRP_MJ_CREATE:
		status = STATUS_SUCCESS;
		break;
	case IRP_MJ_CLOSE:
		status = STATUS_SUCCESS;
		break;
	case IRP_MJ_READ:
		status = STATUS_SUCCESS;
		break;
	case IRP_MJ_WRITE:

		InjectInfo = (PINJECT_INFO)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

		if (!InjectInfo)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		if (!InjectDll(InjectInfo))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		status = STATUS_SUCCESS;
		irp->IoStatus.Information = sizeof(INJECT_INFO);

		break;

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	irp->IoStatus.Status = status;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

