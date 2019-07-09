#include "Driver.h"

NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	NTSTATUS Status;

	__try
	{
		if (NT_SUCCESS(Status = MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &Bytes)))
		{
			Status = STATUS_SUCCESS;
		}
		else
		{
			//gPrintEx(0, 0, "[WGS] " __FUNCTION__ " FAILED | 'Status' => %u, 'Bytes' => %u.\n", Status, Bytes);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();

		if (Status == STATUS_ACCESS_VIOLATION)
		{
			//gPrintEx(0, 0, "[WGS] " __FUNCTION__ " THREW ACCESS VIOLATION.\n");
		}
	}

	return Status;
}

NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	NTSTATUS Status;

	__try
	{
		if (NT_SUCCESS(Status = MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &Bytes)))
		{
			Status = STATUS_SUCCESS;
		}
		else
		{
		//	DbgPrintEx(0, 0, "[WGS] " __FUNCTION__ " FAILED | 'Status' => %u, 'Bytes' => %u.\n", Status, Bytes);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();

		if (Status == STATUS_ACCESS_VIOLATION)
		{
		//	DbgPrintEx(0, 0, "[WGS] " __FUNCTION__ " THREW ACCESS VIOLATION.\n");
		}
	}

	return Status;
}