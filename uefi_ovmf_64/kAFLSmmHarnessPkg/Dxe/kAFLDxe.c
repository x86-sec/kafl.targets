#include "kAFLDxe.h"

#include <Protocol/MmCommunication.h>
#include <Protocol/kAFLDxe.h>

#include <Library/kAFLAgentLib.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/MmUnblockMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Guid/kAFLSmm.h>

EFI_MM_COMMUNICATION2_PROTOCOL *mMmCommunication2 = NULL;

// Communication buffer
UINT8 *mkAFLBuffer = NULL;
#ifdef KAFL_HARNESS_DXE_HIGH
// kAFL payload buffer
kAFL_payload* payload_buffer;
#endif
// UEFI is id mapped same as above
UINT8 *mkAFLBufferPhysical = NULL;
UINTN mkAFLBufferSize = 0;

// Protocol interface handle
EFI_HANDLE mkAFLDxeHandle = NULL;

#ifdef KAFL_HARNESS_DXE_HIGH
void HarnessInit(void *panic_handler, void *kasan_handler)
{
  DebugPrint (DEBUG_INFO, "Initiate fuzzer handshake...\n");

  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_ACQUIRE\n");
  kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_RELEASE\n");
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

  /* submit panic and optionally kasan handlers for qemu
   * override */
  if (panic_handler) {
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, (uint_ptr)panic_handler);
  }

  if (kasan_handler) {
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, (uint_ptr)kasan_handler);
  }
}

void HarnessRun(void) {
  DebugPrint (DEBUG_INFO, "Mapping info: kAFL buffer in heap 0x%016lx\n",
      (void*)payload_buffer);

  DebugPrint (DEBUG_INFO, "SWAG SIZE IN PAGES !: 0x%x\n",
      EFI_SIZE_TO_PAGES(PAYLOAD_SIZE));

  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_GET_PAYLOAD\n");
  kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint_ptr)payload_buffer);

  DebugPrint (DEBUG_INFO, "Payload [%x, %x, %x, %x]\n",
      payload_buffer->data[0],
      payload_buffer->data[1],
      payload_buffer->data[2],
      payload_buffer->data[3]);

  // No CR3 filtering
#ifdef GROSS_TOY_TEST
  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_SUBMIT_CR3\n");
  kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
#else
  DebugPrint (DEBUG_INFO, "No CR3 filtering, crossing SMM boudaries\n");
#endif

  DebugPrint (DEBUG_INFO, "Main loop go !\n");
  DebugPrint (DEBUG_INFO, "@HarnessRun(0x%016lx)\n", HarnessRun);
  while (1) {
    // XXX
// #define GROSS_TOY_TEST
#ifndef GROSS_TOY_TEST
    UINT8 *payload = NULL;
#endif

    // DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_GET_NEXT_PAYLOAD\n");
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

//     DebugPrint (DEBUG_INFO, "Payload [%x, %x, %x, %x]\n",
//         payload_buffer->data[0],
//         payload_buffer->data[1],
//         payload_buffer->data[2],
//         payload_buffer->data[3]);

    // DebugPrint (DEBUG_INFO, "Payload %s\n", (void*)payload_buffer->data);

#ifndef GROSS_TOY_TEST
    InitCommunicateBuffer((void **)&payload, payload_buffer->size,
        KAFL_SMM_FUNCTION_FUZZ);
    ASSERT (payload != NULL);
    CopyMem(payload, payload_buffer->data, payload_buffer->size);
#endif

//     DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_ACQUIRE\n");
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

#ifdef GROSS_TOY_TEST
    uint8_t *p = (void*)payload_buffer->data;
    if (p[0] == 'd') {
      if (p[1] == 'e') {
        if (p[2] == 'a') {
          if (p[3] == 'd') {
            kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
          }
        }
      }
    }
#else
    SendCommunicateBuffer(payload_buffer->size);
#endif

    // DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_RELEASE\n");
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
  }

  return;
}
#endif

//
// kAFL Dxe Protocol
//
EFI_KAFL_DXE_PROTOCOL gkAFLDxe = {
  kAFLDxeNoop,
  kAFLDxeFuzz,
};

EFI_STATUS
EFIAPI
kAFLDxeNoop (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "kAFLDxe: NOOP!\n"));
  InitCommunicateBuffer(NULL, 4, KAFL_SMM_FUNCTION_NOOP);
  SendCommunicateBuffer(4);

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
kAFLDxeFuzz (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "kAFLDxe: FUZZ!\n"));

#ifdef KAFL_HARNESS_DXE_HIGH
  DEBUG ((DEBUG_INFO, "SmmDxeFuzz: Calling HarnessRun...\n"));
  HarnessRun();
#else
  DEBUG ((DEBUG_INFO, "SmmDxeFuzz: Bypass HarnessRun, called after...\n"));
  InitCommunicateBuffer(NULL, 4, KAFL_SMM_FUNCTION_FUZZ);
  SendCommunicateBuffer(4);
#endif

  return EFI_SUCCESS;
}


/**
  Initialize the communicate buffer using DataSize and Function.

  The communicate size is: SMM_COMMUNICATE_HEADER_SIZE +
  SMM_VARIABLE_COMMUNICATE_HEADER_SIZE + DataSize.

  Caution: This function may receive untrusted input.
  The data size external input, so this function will validate it carefully to
  avoid buffer overflow.

  @param[out] DataPtr  Points to the data in the communicate buffer.
  @param[in]  DataSize The data size to send to SMM.
  @param[in]  Function The function number to initialize the communicate header.

  @retval EFI_INVALID_PARAMETER The data size is too big.
  @retval EFI_SUCCESS           Find the specified variable.

**/
EFI_STATUS
InitCommunicateBuffer (
  OUT VOID  **DataPtr OPTIONAL,
  IN  UINTN DataSize,
  IN  UINTN Function
  )
{
  EFI_MM_COMMUNICATE_HEADER *SmmCommunicateHeader;
  SMM_KAFL_COMMUNICATE_HEADER *SmmkAFLFunctionHeader;

  if (DataSize + SMM_COMMUNICATE_HEADER_SIZE + SMM_KAFL_COMMUNICATE_HEADER_SIZE
      > mkAFLBufferSize) {
    return EFI_INVALID_PARAMETER;
  }

  SmmCommunicateHeader = (EFI_MM_COMMUNICATE_HEADER *) mkAFLBuffer;
  CopyGuid (&SmmCommunicateHeader->HeaderGuid, &gkAFLSmmGuid);
  SmmCommunicateHeader->MessageLength = DataSize +
      SMM_KAFL_COMMUNICATE_HEADER_SIZE;

  SmmkAFLFunctionHeader =
      (SMM_KAFL_COMMUNICATE_HEADER *) SmmCommunicateHeader->Data;
  SmmkAFLFunctionHeader->Function = Function;
  if (DataPtr != NULL) {
    *DataPtr = SmmkAFLFunctionHeader->Data;
  }

  return EFI_SUCCESS;
}

/**
  Send the data in communicate buffer to SMM.

  @param[in] DataSize    This size of the function header and the data.

  @retval    EFI_SUCCESS Success is returned from the functin in SMM.
  @retval    Others      Failure is returned from the function in SMM.

**/
EFI_STATUS
SendCommunicateBuffer (
  IN UINTN DataSize
  )
{
  EFI_STATUS Status;
  UINTN CommSize;
  EFI_MM_COMMUNICATE_HEADER *SmmCommunicateHeader;
  SMM_KAFL_COMMUNICATE_HEADER *SmmkAFLFunctionHeader;

  CommSize = DataSize + SMM_COMMUNICATE_HEADER_SIZE +
      SMM_KAFL_COMMUNICATE_HEADER_SIZE;

  DEBUG ((DEBUG_INFO, "Comm buffer NOT SMM 0x%08x!\n", mkAFLBuffer));
  DEBUG ((DEBUG_INFO, "Comm buffer size NOT SMM 0x%08x!\n", CommSize));

  Status = mMmCommunication2->Communicate (mMmCommunication2,
      mkAFLBufferPhysical, mkAFLBuffer, &CommSize);

  DEBUG ((DEBUG_INFO, "Comm buffer NOT SMM 0x%08x!\n", mkAFLBuffer));
  DEBUG ((DEBUG_INFO, "Comm buffer size NOT SMM 0x%08x!\n", CommSize));

  ASSERT_EFI_ERROR (Status);

  // TODO XXX WTF this thing is here ? Reallocation by MM lib ?
  SmmCommunicateHeader = (EFI_MM_COMMUNICATE_HEADER *) mkAFLBuffer;
  SmmkAFLFunctionHeader =
      (SMM_KAFL_COMMUNICATE_HEADER *) SmmCommunicateHeader->Data;
  return SmmkAFLFunctionHeader->ReturnStatus;
}

/**
  The driver's entry point.

  kAFL DXE driver working in conjunction with SMM one

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point is executed successfully.
  @retval Others          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
InitializekAFLDxe (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  DEBUG ((DEBUG_INFO, "Loading kAFLDxePkg DXE_DRIVER!\n"));

  Status = gBS->LocateProtocol (&gEfiMmCommunication2ProtocolGuid, NULL,
      (VOID **) &mMmCommunication2);
  ASSERT_EFI_ERROR (Status);

  //
  // Allocate memory for variable communicate buffer.
  //
  mkAFLBufferSize = SMM_COMMUNICATE_HEADER_SIZE +
    SMM_KAFL_COMMUNICATE_HEADER_SIZE + PAYLOAD_DATA_SIZE;
  mkAFLBuffer = AllocateRuntimePool(mkAFLBufferSize);
  ASSERT (mkAFLBuffer != NULL);

  // Save physical address which is BTW the same because of UEFI id mapping
  mkAFLBufferPhysical = mkAFLBuffer;

  //
  // Install kAFL Dxe Protocol
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mkAFLDxeHandle,
                  &gEfikAFLDxeProtocolGuid, &gkAFLDxe,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

#ifdef KAFL_HARNESS_DXE_HIGH
  //
  // Allocate memory for kAFL payload buffer
  //
  payload_buffer = AllocatePages(EFI_SIZE_TO_PAGES(PAYLOAD_SIZE));
  DebugPrint (DEBUG_INFO, "Mapping info: kAFL buffer in stack 0x%016lx\n",
      (void*)payload_buffer);

  DEBUG ((DEBUG_INFO, "SmmkAFLHandler: init kAFL...\n"));
  HarnessInit(NULL, NULL);
#endif

  DEBUG ((DEBUG_INFO, "kAFLDxePkg DXE_DRIVER loaded and ready to be used!\n"));

  return Status;
}
