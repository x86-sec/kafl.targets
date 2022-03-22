#!/bin/bash
#
# kAFL helper script to build and launch UEFI components
#
# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: MIT
#

set -e

unset EDK_TOOLS_PATH
unset WORKSPACE
unset CONF_PATH
unset PACKAGES_PATH

TARGET_ROOT="$(dirname ${PWD}/${0})"
[ -n "$KAFL_ROOT" ] || KAFL_ROOT=${PWD}
[ -n "$EDK2_ROOT" ] || EDK2_ROOT=$KAFL_ROOT/edk2.git

[ -d $KAFL_ROOT/kafl_fuzzer ] || ( echo "Please set correct KAFL_ROOT" ; false )

#BUILD=RELEASE
# BUILD=DEBUG
BUILD=NOOPT
#ARCH=IA32
#ARCH=X64
ARCH=3264
TOOL=GCC5

#APP=TestDecompress
#APP=TestBMP
APP=TestToy

#BUILD_OPTS="-a IA32 -a X64 -b NOOPT -t CLANGSAN40 -n 8 -DDEBUG_ON_SERIAL_PORT"
#BUILD_OPTS="-a $ARCH -b $BUILD -t $TOOL -n $(nproc)"
BUILD_OPTS=""
OVMF_DSC_ARCH=""

if test $ARCH = "X64"
then
  BUILD_OPTS="-a X64"
  OVMF_DSC_ARCH="X64"
elif test $ARCH = "IA32"
then
  BUILD_OPTS="-a IA32"
  OVMF_DSC_ARCH="Ia32"
elif test $ARCH = "3264"
then
  BUILD_OPTS="-a IA32 -a X64"
  OVMF_DSC_ARCH="Ia32X64"
else
  echo "Bad target architecture configuration"
  exit 1
fi

BUILD_OPTS="${BUILD_OPTS} \
  -t ${TOOL} \
  -b ${BUILD} \
  -n $(nproc)"

KAFL_OPTS="--redqueen --hammer_jmp_tables --grimoire --catch_reset -v --log --debug --trace"

function install_edk2()
{
	# requirements on top of kAFL base install
  # Adapt to pacman
	# sudo apt-get install nasm iasl g++ g++-multilib
	
	# download + apply patch unless install folder already exists
	if [ -d $KAFL_ROOT/edk2.git ]; then
		echo "[*] Folder exists, assume it is already patched.."
		pushd $KAFL_ROOT/edk2.git
	else
		git clone https://github.com/tianocore/edk2 $KAFL_ROOT/edk2.git
		pushd $KAFL_ROOT/edk2.git
		git checkout -b edk2-stable202108
		git submodule update --init --recursive
		patch -p1 < $TARGET_ROOT/edk2_kafl.patch || exit
		patch -p1 < $TARGET_ROOT/edk2_kafl_smm.patch || exit
	fi
	make -C BaseTools -j $(nproc)
	export EDK_TOOLS_PATH=$PWD/BaseTools
	. edksetup.sh BaseTools
	popd
}

function build_smm_platform()
{
  echo
  echo Building package $1, output platform name $2
  echo
  sleep 1


BUILD_OPTS="${BUILD_OPTS} \
  -D SMM_REQUIRE -D SECURE_BOOT_ENABLE \
  -D HTTP_BOOT_ENABLE -D TLS_ENABLE"

	[ -d $EDK2_ROOT/BaseTools ] || ( echo "Please set correct EDK2_ROOT"; exit )
	pushd $EDK2_ROOT
	export PACKAGES_PATH=$TARGET_ROOT
	export EDK_TOOLS_PATH=$PWD/BaseTools
	. edksetup.sh BaseTools

	which build || exit

  # Already built with my OVMF platform
  # @see in kAFLSmmHarnessPkg/App/kAFLApp.inf
  build $BUILD_OPTS -p "$1/kAFLSmmPlatform.dsc"

	echo "Build done, copy target files.."
  # Copy new platform
	cp -v "Build/$2/${BUILD}_${TOOL}/FV/OVMF.fd" $TARGET_ROOT/bios.bin
	cp -v "Build/$2/${BUILD}_${TOOL}/FV/OVMF_CODE.fd" $TARGET_ROOT
	cp -v "Build/$2/${BUILD}_${TOOL}/FV/OVMF_VARS.fd" $TARGET_ROOT

  # Need a key to sign harness image
  if test ! -f $TARGET_ROOT/OVMFKeys/PK.key
  then
    secure_boot_keys
  fi

  # XXX Should distinguish OVMF target architecture from harness architecture
	# cp -v "Build/$2/${BUILD}_${TOOL}/X64/kAFLApp.efi" $TARGET_ROOT/fake_hda/kAFLApp.efi
  sbsign --key $TARGET_ROOT/OVMFKeys/db.key --cert $TARGET_ROOT/OVMFKeys/db.crt "Build/$2/${BUILD}_${TOOL}/X64/kAFLApp.efi" --output $TARGET_ROOT/fake_hda/kAFLApp.efi
	popd
}

function build_smm_dxe_high_lock_box()
{
  build_smm_platform kAFLSmmPlatformSmmDxeHighLockBoxPkg kAFLSmmDxeHighLockBox
}

function build_smm_dxe_high_password()
{
  build_smm_platform kAFLSmmPlatformSmmDxeHighPasswordPkg kAFLSmmDxeHighPassword
}

function build_null()
{
  build_smm_platform kAFLSmmPlatformNullPkg kAFLNull
}

function build_smm_dxe_high_dummy()
{
  build_smm_platform kAFLSmmPlatformSmmDxeHighDummyPkg kAFLSmmDxeHighDummy
}

function build_dxe_high_dummy()
{
  build_smm_platform kAFLSmmPlatformDxeHighDummyPkg kAFLDxeHighDummy
}

function build_smm_dxe_high_auth_variable()
{
  build_smm_platform kAFLSmmPlatformSmmDxeHighAuthVariablePkg kAFLSmmDxeHighAuthVariable
}

function run()
{
	pushd $KAFL_ROOT
	# Note: -ip0 depends on your UEFI build and provided machine memory!
	# python3 kafl_fuzz.py -ip0 0xF000000-0xFF00000 --purge \
	# python3 kafl_fuzz.py -ip0 0xE000000-0xEF00000 --purge \
	# python3 kafl_fuzz.py --purge \
	python3 kafl_fuzz.py -ip0 0xE000000-0xEF00000 -ip1 0xF000000-0xFF00000 --purge \
		--flash $TARGET_ROOT/OVMF_CODE.fd $TARGET_ROOT/OVMF_VARS.fd \
		--qemu-extra " -hda fat:rw:$TARGET_ROOT/fake_hda -net none -no-reboot" \
		--memory 256 \
		--seed_dir $TARGET_ROOT/seeds/ \
		--work_dir /dev/shm/kafl_uefi \
		$KAFL_OPTS $*
	popd
}

# Replay seeds only to debug them using gdbserver
function analyze()
{
  KAFL_OPTS_="-p 1 -redqueen -hammer_jmp_tables -grimoire -catch_reset -gdbserver -v --log --debug -trace"
  echo Using $1 as seed directory
  p=`realpath $1`; shift
  if test ! -d $p
  then
    echo $p is does not exist
    exit 1
  fi
	pushd $KAFL_ROOT
	python3 kafl_fuzz.py --purge \
		--flash $TARGET_ROOT/OVMF_CODE.fd $TARGET_ROOT/OVMF_VARS.fd \
		--qemu-extra " -hda fat:rw:$TARGET_ROOT/fake_hda -net none -no-reboot" \
		--memory 256 \
		--seed_dir "$p" \
		--work_dir /dev/shm/kafl_uefi \
		$KAFL_OPTS_ $*
	popd
}

function noise()
{
	pushd $KAFL_ROOT
	TEMPDIR=$(mktemp -d -p /dev/shm)
	WORKDIR=$1; shift
	echo
	echo "Using temp workdir >>$TEMPDIR<<.."
	echo
	sleep 1

	# Note: -ip0 and other VM settings should match those used during fuzzing
	python3 kafl_debug.py -action noise -ip0 0x2000000-0x2F00000 --purge \
		--bios $TARGET_ROOT/bios.bin \
		--qemu-extra " -hda fat:rw:$TARGET_ROOT/fake_hda -net none -no-reboot" \
		--memory 64 \
		--work_dir $TEMPDIR \
		--input $WORKDIR $*
	popd
}

function cov()
{
	pushd $KAFL_ROOT
	TEMPDIR=$(mktemp -d -p /dev/shm)
	WORKDIR=$1
	echo
	echo "Using temp workdir >>$TEMPDIR<<.."
	echo
	sleep 1

	# Note: -ip0 and other VM settings should match those used during fuzzing
	python3 kafl_cov.py -v -ip0 0x2000000-0x2F00000 --purge \
		--bios $TARGET_ROOT/bios.bin \
		--qemu-extra " -hda fat:rw:$TARGET_ROOT/fake_hda -net none -no-reboot" \
		--memory 64 \
		--work_dir $TEMPDIR \
		--input $WORKDIR
	popd
}

function secure_boot_keys()
{
	pushd $KAFL_ROOT
	echo
	echo "Creating secure boot keys.."
	echo
	sleep 1

 bash $TARGET_ROOT/efi-mkkeys/efi-mkkeys -s "Intel Corp" -b 2048 -d 365 -o $TARGET_ROOT/OVMFKeys
 cp -vr $TARGET_ROOT/OVMFKeys/{*.auth,*.esl,*.cer} $TARGET_ROOT/fake_hda

	popd
}

function secure_boot_prepare(){
	echo
	echo "Copy PK.der key to fake hda and run qemu to let the user import the keys.."
	echo
	sleep 1

  run -C
}

function usage() {
	echo
	echo "Build and run the UEFI OVMF sample."
	echo
	echo "This script assumes KAFL at $KAFL_ROOT and EDK2 cloned to $EDK2_ROOT."
	echo "Build settings in Conf/target.txt will be overridden with '$BUILD_OPTS'."
	echo
	echo "Usage: $0 <edk2|ovmf|app|run>"
	echo
	echo Parameters:
	echo "  edk2                         - download edk2 branch + build deps"
	echo "  dxe_high_dummy               - build kAFL Dxe Dummy Fuzzing platform"
	echo "  smm_dxe_high_dummy           - build kAFL Smm Dxe Dummy Fuzzing platform"
	echo "  smm_dxe_high_password        - build kAFL Smm Dxe Password Fuzzing platform"
	echo "  smm_dxe_high_lock_box        - build kAFL Smm Dxe Lock Box Fuzzing platform"
	echo "  smm_dxe_high_auth_variable   - build kAFL Smm Dxe Auth Variable Fuzzing platform"
	echo "  smm_null                     - build kAFL Smm Dxe NULL Fuzzing platform"
	echo "  analyze <seed_dir>           - run on seeds only with no feedback normutation."
  echo "                                 Activates gdb and force to one core."
  echo "                                 Intended to be used for post mortem or post fuzzing session analysis"
	echo "  run                          - run sample agent in kAFL"
	echo "  cov <dir>                    - process <dir> in trace mode to collect coverage info"
	echo "  noise <file>                 - process <file> in trace mode to collect coverage info"
	echo "  secure_boot_keys             - Generate secure boot keys"
	echo "  secure_boot_prepare          - Copy secure boot keys to fake hda and run qemu to let user import MANUALLY PKs"
	exit
}


CMD=$1; shift || usage

case $CMD in
	"run")
		run $*
		;;
	"noise")
		test -f "$1" || usage
		noise $*
		;;
	"cov")
		test -d "$1" || usage
		cov $1
		;;
	"edk2")
		install_edk2
		;;
	"dxe_high_dummy")
		build_dxe_high_dummy
		;;
	"smm_dxe_high_dummy")
		build_smm_dxe_high_dummy
		;;
	"smm_dxe_high_lock_box")
		build_smm_dxe_high_lock_box
		;;
	"smm_dxe_high_password")
		build_smm_dxe_high_password
		;;
	"smm_null")
		build_null
		;;
	"smm_dxe_high_auth_variable")
		build_smm_dxe_high_auth_variable
		;;
	"analyze")
		analyze $*
		;;
	"secure_boot_keys")
		secure_boot_keys $*
		;;
	"secure_boot_prepare")
		secure_boot_prepare $*
		;;
	*)
		usage
		;;
esac
