#ifndef _KAFL_SMM_H_
#define _KAFL_SMM_H_

#include <Protocol/MmCommunication2.h>

#define EFI_KAFL_SMM_GUID \
  { 0x93fe1856, 0xdffb, 0x45dd, \
    { 0x82, 0xa7, 0xe7, 0xca, 0xac, 0xca, 0xac, 0xf3 }}

extern EFI_GUID gkAFLSmmGuid;

//
// This structure is used for SMM kAFL. The collected statistics data is
// saved in SMRAM. It can be got from SMI handler. The communication buffer
// should be:
// EFI_MM_COMMUNICATE_HEADER + SMM_KAFL_COMMUNICATE_HEADER + payload.
//
typedef struct {
  UINTN       Function;
  EFI_STATUS  ReturnStatus;
  UINT8       Data[];
} SMM_KAFL_COMMUNICATE_HEADER;

//
// Available SMM DXE driver kAFL functions
//
enum kafl_smm_functions {
  KAFL_SMM_FUNCTION_NOOP,
  KAFL_SMM_FUNCTION_FUZZ,
};

///
/// Size of SMM communicate header, without including the payload.
///
#define SMM_COMMUNICATE_HEADER_SIZE  (OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data))

///
/// Size of SMM variable communicate header, without including the payload.
///
#define SMM_KAFL_COMMUNICATE_HEADER_SIZE  (OFFSET_OF (SMM_KAFL_COMMUNICATE_HEADER, Data))

#endif//_KAFL_SMM_H_
