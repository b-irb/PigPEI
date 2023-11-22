#!/usr/bin/env sh

set -euo 1>/dev/null

FV=fv
TARGET=target/x86_64-none-uefi/debug/pig.efi

cargo build

[ -f $TARGET ] || exit 1
uefireplace $FV/OVMF_CODE.fd $(cat uuid) 10 $TARGET 1>/dev/null

# Create a UEFI environment with mounted OVMF firmware and
# ISA exit device mapped at 0x501 I/O address.
qemu-system-x86_64 \
    -s \
    -nographic \
    -machine type=q35,accel=kvm:tcg \
    -m 512 \
    -drive file=$FV/OVMF_CODE.fd.patched,format=raw,if=pflash \
    -drive file=$FV/OVMF_VARS.fd,format=raw,if=pflash \
    -device isa-debug-exit \
    -debugcon file:debug.log -global isa-debugcon.iobase=0x402 \
    -nodefaults \
    -monitor none -serial stdio
