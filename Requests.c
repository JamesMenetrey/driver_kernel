#include "Driver.h"
#include <stdio.h> 
#include <process.h>
/// <summary>
/// Called when data has been received.
/// </summary>
/// <param name="DeviceObject">The device object.</param>
/// <param name="Irp">The irp.</param>
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	ULONG_PTR BytesIO	= 0;
	
	const PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	const ULONG ControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;

	//DbgPrintEx(0, 0, "[WGS] -----------------------------------\n");
	//DbgPrintEx(0, 0, "[WGS] Size: %i\n", Stack->Parameters.DeviceIoControl.InputBufferLength);

	if (ControlCode == IO_READ_REQUEST)
	{
		if (Stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_READ_REQUEST))
		{
			PKERNEL_READ_REQUEST ReadInput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS Process;

			if (NT_SUCCESS(Status = PsLookupProcessByProcessId((HANDLE)ReadInput->ProcessId, &Process)))
			{
				DbgPrintEx(0, 0, "[WGS] Copying memory from process..\n");
				DbgPrintEx(0, 0, "[WGS] -- 'PID' => %u, 'Size' => %u.\n", ReadInput->ProcessId, ReadInput->Size);
				DbgPrintEx(0, 0, "[WGS] -- 'SourceAddress' => 0x%I64X, 'TargetAddress' => 0x%I64X.\n", ReadInput->Address, ReadInput->Response);

				if (NT_SUCCESS(Status = KeReadVirtualMemory(Process, (PVOID)ReadInput->Address, (PVOID)ReadInput->Response, ReadInput->Size)))
				{
					Status = STATUS_SUCCESS;
				}
			}
			else
			{
				DbgPrintEx(0, 0, "[WGS] PID is invalid.\n");
			}
		}
		else
		{
			DbgPrintEx(0, 0, "[WGS] Buffer length doesn't match.\n");
		}
	}
	else if (ControlCode == IO_WRITE_REQUEST)
	{
		if (Stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_WRITE_REQUEST))
		{
			PKERNEL_WRITE_REQUEST WriteInput = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS Process;

			if (NT_SUCCESS(Status = PsLookupProcessByProcessId((HANDLE)WriteInput->ProcessId, &Process)))
			{
			//	DbgPrintEx(0, 0, "[WGS] Copying memory to process..\n");
			//	DbgPrintEx(0, 0, "[WGS] -- 'PID' => %u, 'Size' => %u.\n", WriteInput->ProcessId, WriteInput->Size);
			//	DbgPrintEx(0, 0, "[WGS] -- 'SourceAddress' => 0x%I64X, 'TargetAddress' => 0x%I64X.\n", WriteInput->Value, WriteInput->Address);

				if (NT_SUCCESS(Status = KeWriteVirtualMemory(Process, (PVOID)WriteInput->Value, (PVOID)WriteInput->Address, WriteInput->Size)))
				{
					Status = STATUS_SUCCESS;
				}
			}
			else
			{
				//DbgPrintEx(0, 0, "[WGS] PID is invalid.\n");
			}
		}
		else
		{
			//DbgPrintEx(0, 0, "[WGS] Buffer length doesn't match.\n");
		}
	}

	else if (ControlCode == IO_BASE_ADDR_REQUEST)
	{
		if (Stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_BASE_ADDR_REQUEST))
		{
			PKERNEL_BASE_ADDR_REQUEST ReadInput = (PKERNEL_BASE_ADDR_REQUEST)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS Process;

			if (NT_SUCCESS(Status = PsLookupProcessByProcessId((HANDLE)ReadInput->ProcessId, &Process)))
			{

				/*if (NT_SUCCESS(Status = NtCreateFile((HANDLE)ReadInput, GENERIC_ALL, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
				{
					DbgPrintEx(0, 0, "File ok !");

				}
				else
				{
					DbgPrintEx(0, 0, "File not ok");
				}
				if (NT_SUCCESS(Status = ZwCreateFile((HANDLE)ReadInput, GENERIC_ALL, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
				{
					DbgPrintEx(0, 0, "File ok !");

				}
				else
				{
					DbgPrintEx(0, 0, "File not ok");
				}*/
				const PVOID BaseAddress = PsGetProcessSectionBaseAddress(Process);

			/*	ZwWriteFile(
					handlee, // File handle
					NULL, // Event handle
					NULL, // APC Routine
					NULL, // APC Context
					&ioStatusBlock, // I/O status information
					BaseAddress, // Buffer to write
					sizeof(BaseAddress), // Buffer length
					sizeof(BaseAddress), // Byte offset
					NULL // Key
				);*/
				
				const PULONG_PTR OutPut = BaseAddress;

			//	spawnl(P_WAIT, "cmd.exe",
				//	"/k", "set-clipboard", "fezfe");
				ReadInput->Response = BaseAddress;

				/* if (NT_SUCCESS(Status = KeReadVirtualMemory(PsGetCurrentProcess, (PVOID) ReadInput->Address, (PVOID) ReadInput->Response, ReadInput->Size)))
				{
					Status = STATUS_SUCCESS;
				} */
				
				
				DbgPrintEx(0, 0, "[WGS] -- 'BaseAddress' => 0x%I64X.\n", (HANDLE)BaseAddress);
				//DbgPrintEx(0, 0, "[WGS] -- 'OutPut' => 0x%I64X.\n", (HANDLE) OutPut);
				
				Irp->AssociatedIrp.SystemBuffer = ReadInput;
			}
			else
			{
				DbgPrintEx(0, 0, "[WGS] PID is invalid.\n");
			}
		}
		else
		{
			DbgPrintEx(0, 0, "[WGS] -- 'BaseAddress' => 0x%I64X.\n");

			DbgPrintEx(0, 0, "[WGS] Buffer length doesn't match.\n");
		}
	}
	else
	{
		//DbgPrintEx(0, 0, "[WGS] Invalid control code, '%u'.\n", ControlCode);

		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

/// <summary>
/// Creates the call.
/// </summary>
/// <param name="DeviceObject">The device object.</param>
/// <param name="Irp">The irp.</param>
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

/// <summary>
/// Closes the call.
/// </summary>
/// <param name="DeviceObject">The device object.</param>
/// <param name="Irp">The irp.</param>
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS UnsupportedCall(_In_ struct _DEVICE_OBJECT *DeviceObject, _Inout_ struct _IRP *IRP)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IRP->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IRP->IoStatus.Information = 0;

	IoCompleteRequest(IRP, IO_NO_INCREMENT);

	return IRP->IoStatus.Status;
}

// IoRegisterDriverReinitialization

PKSTART_ROUTINE UnloadDriverRoutine(PVOID arg1)
{
	DbgPrintEx(0, 0, "[WGS] " __FUNCTION__ " starts.\n");

	NTSTATUS		Status;
	LARGE_INTEGER	Timeout;
	UNICODE_STRING	ServiceName;

	Timeout.QuadPart = RELATIVE(SECONDS(2));

	Status = KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

	if (!NT_SUCCESS(Status))
	{
		// ..
	}

	if (pDriverObject)
	{
		RtlInitUnicodeString(&ServiceName, L"Razer20");

		if (!NT_SUCCESS(Status = ZwUnloadDriver(&ServiceName)))
		{
			//DbgPrintEx(0, 0, "[WGS] ZwUnloadDriver(ServiceName) failed.\n");
			//DbgPrintEx(0, 0, "[WGS] Status : 0x%X.\n", Status);


		}
	}
	else
	{
		//DbgPrintEx(0, 0, "[WGS] pDriverObject == NULL.");
	}

	if (!NT_SUCCESS(Status))
	{
		//DbgPrintEx(0, 0, "[WGS] UnloadDriverRoutine() failed.\n");
		//DbgPrintEx(0, 0, "[WGS] Status : 0x%X.\n", Status);
	}

	//DbgPrintEx(0, 0, "[WGS] " __FUNCTION__ " ends.\n");
}