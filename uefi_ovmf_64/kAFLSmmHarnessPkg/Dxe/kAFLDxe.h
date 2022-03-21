/** @file
  The header file for kAFL driver.
**/

#ifndef __KAFL_DXE_PKG_H__
#define __KAFL_DXE_PKG_H__

EFI_STATUS
EFIAPI
kAFLDxeNoop (
  VOID
  );

EFI_STATUS
EFIAPI
kAFLDxePrint (
  VOID
  );

EFI_STATUS
EFIAPI
kAFLDxePf (
  VOID
  );

EFI_STATUS
EFIAPI
kAFLDxeFuzz (
  VOID
  );

EFI_STATUS
InitCommunicateBuffer (
  OUT VOID  **DataPtr OPTIONAL,
  IN  UINTN DataSize,
  IN  UINTN Function
  );

EFI_STATUS
SendCommunicateBuffer (
  IN UINTN DataSize
  );

#endif//__KAFL_DXE_PKG_H__
