#include "kAFLSmmDxe.h"

#include <Library/kAFLAgentLib.h>
#include <Library/kAFLSmmTargetLib.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/MmServicesTableLib.h>
#include <Library/BmpSupportLib.h>
#include <Library/CpuExceptionHandlerLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Guid/kAFLSmm.h>

void crash(void) {
  kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
  while (1);
}

uint8_t *buffer;

#ifdef KAFL_HARNESS_SMM_DXE_HIGH
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

void HarnessRun()
{
    // uint8_t buffer[PAYLOAD_SIZE];
    // Make sure it is page aligned
    buffer = AllocatePool(PAYLOAD_SIZE + 0x1000);
    buffer = (uint8_t*)(((uint64_t)buffer + 0x1000) & 0xfffffffffffff000);
    kAFL_payload* payload_buffer = (kAFL_payload*)buffer;

    DebugPrint (DEBUG_INFO, "Mapping info: kAFL buffer in SMM pool 0x%016lx\n",
        (void*)buffer);

    DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_GET_PAYLOAD\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint_ptr)payload_buffer);

    DebugPrint (DEBUG_INFO, "Payload [%x, %x, %x, %x]\n",
        payload_buffer->data[0],
        payload_buffer->data[1],
        payload_buffer->data[2],
        payload_buffer->data[3]);

    DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_SUBMIT_CR3\n");
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    DebugPrint (DEBUG_INFO, "Mapping info: kAFL buffer in stack 0x%016lx\n",
        (void*)buffer);


   DebugPrint (DEBUG_INFO, "Main loop go !\n");
    while (1) {
//         DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_GET_NEXT_PAYLOAD\n");
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

//         DebugPrint (DEBUG_INFO, "Payload [%x, %x, %x, %x]\n",
//             payload_buffer->data[0],
//             payload_buffer->data[1],
//             payload_buffer->data[2],
//             payload_buffer->data[3]);
// 
//         DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_ACQUIRE\n");
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

//         DebugPrint (DEBUG_INFO, "Payload %s\n", (void*)payload_buffer->data);
        RunkAFLTarget(payload_buffer->data, payload_buffer->size);

//         DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_RELEASE\n");
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }

    FreePool(buffer);

    return;
}
#endif

/**
  Communication service SMI Handler entry.

  This SMI handler provides services for the variable kAFL Smm Dxe driver.

  Caution: This function may receive untrusted input.
  This variable data and communicate buffer are external input, so this function
  will do basic validation.

  @param[in]     DispatchHandle  The unique handle assigned to this handler by
                                 SmiHandlerRegister().
  @param[in]     RegisterContext Points to an optional handler context which was
                                 specified when the handler was registered.
  @param[in, out] CommBuffer     A pointer to a collection of data in memory
                                 that will be conveyed from a non-SMM
                                 environment into an SMM environment.
  @param[in, out] CommBufferSize The size of the CommBuffer.

  @retval EFI_SUCCESS                         The interrupt was handled and
                                              quiesced. No other handlers
                                              should still be called.
  @retval EFI_WARN_INTERRUPT_SOURCE_QUIESCED  The interrupt has been quiesced
                                              but other handlers should still
                                              be called.
  @retval EFI_WARN_INTERRUPT_SOURCE_PENDING   The interrupt is still pending and
                                              other handlers should still be
                                              called.
  @retval EFI_INTERRUPT_PENDING               The interrupt could not be
                                              quiesced.
**/
EFI_STATUS
EFIAPI
SmmkAFLHandler (
  IN     EFI_HANDLE                                       DispatchHandle,
  IN     CONST VOID                                       *RegisterContext,
  IN OUT VOID                                             *CommBuffer,
  IN OUT UINTN                                            *CommBufferSize
  )
{
  UINTN TempCommBufferSize;
  UINTN CommBufferPayloadSize;

  DEBUG ((DEBUG_INFO, "kAFLSmmHarnessPkg SMI handler !\n"));

  // DEBUG ((DEBUG_INFO, "Comm buffer IN SMM 0x%08x!\n", CommBuffer));
  // DEBUG ((DEBUG_INFO, "Comm buffer size IN SMM 0x%08x!\n", *CommBufferSize));

  //
  // If input is invalid, stop processing this SMI
  //
  if (CommBuffer == NULL || CommBufferSize == NULL) {
    return EFI_SUCCESS;
  }

  TempCommBufferSize = *CommBufferSize;

  if (TempCommBufferSize < SMM_KAFL_COMMUNICATE_HEADER_SIZE) {
    DEBUG ((EFI_D_ERROR,
        "SmmkAFLHandler: SMM communication buffer size invalid!\n"));
    return EFI_SUCCESS;
  }

  CommBufferPayloadSize = TempCommBufferSize -
      SMM_KAFL_COMMUNICATE_HEADER_SIZE;
  if (CommBufferPayloadSize > PAYLOAD_SIZE) {
    DEBUG ((EFI_D_ERROR,
        "SmmVariableHandler: SMM communication buffer payload size "
        "invalid!\n"));
    return EFI_SUCCESS;
  }

  SMM_KAFL_COMMUNICATE_HEADER *msg = (SMM_KAFL_COMMUNICATE_HEADER *) CommBuffer;

  switch (msg->Function) {
    case KAFL_SMM_FUNCTION_NOOP:
      DEBUG ((DEBUG_INFO, "SmmkAFLHandler: NOOP\n"));
      break;
    case KAFL_SMM_FUNCTION_FUZZ:
      DEBUG ((DEBUG_INFO, "SmmkAFLHandler: FUZZ\n"));
#ifdef KAFL_HARNESS_SMM_DXE_HIGH
      DEBUG ((DEBUG_INFO, "SmmkAFLHandler: Calling HarnessRun...\n"));
      HarnessRun();
#else
      DEBUG ((DEBUG_INFO, "SmmkAFLHandler: Bypass HarnessRun, "
          "harness is ran before...\n"));
      // XXX
      // TODO modify this to use communication buffer payload
      //
      kAFL_payload* payload_buffer = (kAFL_payload*)&msg->Data;
      RunkAFLTarget(payload_buffer->data, payload_buffer->size);
#endif
      break;
    default:
      DEBUG ((EFI_D_ERROR, "SmmkAFLHandler: invalid function!\n"));
  }

  return EFI_SUCCESS;
}

/**
  The driver's entry point.

  kAFL SMM DXE driver

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point is executed successfully.
  @retval Others          Some error occurs when executing this entry point.

**/
extern void _text_section_start(void);
extern void _text_section_end(void);

EFI_STATUS
EFIAPI
InitializekAFLSmmDxe (
  IN EFI_HANDLE                  ImageHandle,
  IN EFI_SYSTEM_TABLE            *SystemTable
  )
{

  EFI_STATUS Status;  EFI_HANDLE VariableHandle;

  DEBUG ((DEBUG_INFO, "Loading kAFLSmmHarnessPkg SMM_DXE_DRIVER!\n"));

  DEBUG ((DEBUG_INFO, "%s: .text section -ip0 0x%08x-0x%08x\n", __func__,
        &_text_section_start, &_text_section_end));

  //
  // Register SMM SMI handler
  //
  VariableHandle = NULL;
  // Guid to NULL to catch all the SMis !!!!
  Status = gMmst->MmiHandlerRegister (SmmkAFLHandler,
      &gkAFLSmmGuid, &VariableHandle);
  ASSERT_EFI_ERROR (Status);

#ifdef KAFL_HARNESS_SMM_DXE_HIGH
  DEBUG ((DEBUG_INFO, "InitializekAFLSmmDxe: Init kAFL harness...\n"));
  // Sending panic outside SMRAM fails because of breakpoint planting
  // failing. SMI handler can't write outside SMRAM (SMAP)
  // HarnessInit(DumpCpuContext, NULL);
  // HarnessInit(crash, NULL);
  HarnessInit(NULL, NULL);
#endif

  /* target-specific initialization, if any */
  DebugPrint (DEBUG_INFO, "Call InitkAFLTarget\n");
  InitkAFLTarget();

  return Status;
}
