[Defines]
  !include OvmfPkg/OvmfPkgIa32X64.dsc

[Defines]
  PLATFORM_NAME                  = kAFLSmm
  PLATFORM_GUID                  = DFA5E931-0F48-404F-9AE9-35B80EA9FE56
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/kAFLNull
  SUPPORTED_ARCHITECTURES        = IA32|X64
  BUILD_TARGETS                  = NOOPT|DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT
  FLASH_DEFINITION               = kAFLSmmPlatformNullPkg/kAFLSmmPlatform.fdf

  # Mandatory for SMM setup
  DEFINE SMM_REQUIRE = TRUE
  DEFINE SECURE_BOOT_ENABLE = TRUE
  DEFINE HTTP_BOOT_ENABLE = TRUE
  DEFINE TLS_ENABLE = TRUE
  # Harnessing location
  DEFINE HARNESS_LOCATION_NONE = 0
  DEFINE HARNESS_LOCATION_DXE_HIGH = 1
  DEFINE HARNESS_LOCATION_DXE_LOW = 2
  DEFINE HARNESS_LOCATION_SMM_DXE_LOW = 3
  DEFINE HARNESS_LOCATION_SMM_DXE_HIGH = 4
  DEFINE KAFL_HARNESS_LOCATION = $(HARNESS_LOCATION_NONE)

[LibraryClasses]
  kAFLAgentLib|kAFLAgentPkg/Library/kAFLAgentLib/kAFLAgentLib.inf
!if $(SMM_REQUIRE) == TRUE
  kAFLSmmTargetLib|kAFLSmmTargetNullPkg/Library/kAFLSmmTargetLib/kAFLSmmTargetLib.inf
!endif

[Components.X64]
!if $(SMM_REQUIRE) == TRUE
  #
  # SMM harness
  #
  kAFLSmmHarnessPkg/SmmDxe/kAFLSmmDxe.inf
  kAFLSmmHarnessPkg/Dxe/kAFLDxe.inf
  kAFLSmmHarnessPkg/App/kAFLApp.inf
!endif

[BuildOptions]

*_*_*_CC_FLAGS             = -DKAFL_HARNESS_EXTERNAL_AGENT_INIT
*_*_*_CC_FLAGS             = $(*_*_*_CC_FLAGS) -DKAFL_HARNESS_EXTERNAL_AGENT_RUN
*_*_*_CC_FLAGS             = $(*_*_*_CC_FLAGS) -DKAFL_HARNESS_EXTERNAL_UEFI_MAIN

!if $(KAFL_HARNESS_LOCATION) == $(HARNESS_LOCATION_DXE_HIGH)
  *_*_*_CC_FLAGS             = $(*_*_*_CC_FLAGS) -DKAFL_HARNESS_DXE_HIGH
!endif
!if $(KAFL_HARNESS_LOCATION) == $(HARNESS_LOCATION_DXE_LOW)
  *_*_*_CC_FLAGS             = $(*_*_*_CC_FLAGS) -DKAFL_HARNESS_DXE_LOW
!endif
!if $(KAFL_HARNESS_LOCATION) == $(HARNESS_LOCATION_SMM_DXE_LOW)
  *_*_*_CC_FLAGS             = $(*_*_*_CC_FLAGS) -DKAFL_HARNESS_SMM_DXE_LOW
!endif
!if $(KAFL_HARNESS_LOCATION) == $(HARNESS_LOCATION_SMM_DXE_HIGH)
  *_*_*_CC_FLAGS             = $(*_*_*_CC_FLAGS) -DKAFL_HARNESS_SMM_DXE_HIGH
!endif
