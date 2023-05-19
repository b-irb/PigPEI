#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![feature(panic_info_message)]
#![feature(pointer_byte_offsets)]

use core::fmt::Write;
use core::panic::PanicInfo;
use core::ffi;

mod uart;
#[macro_use]
mod log;
#[macro_use]
mod efi;
#[macro_use]
mod pei;
mod asm;
mod dxe;
mod hooks;

use asm::{outb, cli, hlt};
use efi::{EfiStatus};
use pei::{PeiServices, BootMode};

type Cptr = *const ffi::c_void;

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    // panic will provide a default message and invocation location.
    let message = info.message().unwrap();
    let location = info.location().unwrap();
    error!("{} at {}", message, location);
    // Attempt to write to QEMU ISA debug exit device or hcf.
    unsafe { outb(0x501, 1) };
    warn!("QEMU did not quit...");
    loop { unsafe { cli(); hlt() } }
}

fn get_boot_mode(svc: &&mut PeiServices) -> BootMode {
    let mut boot_mode = BootMode::FullConfig;
    if (svc.get_boot_mode)(svc, &mut boot_mode) != EfiStatus::Success {
        panic!("call to GetBootMode() failed")
    }
    boot_mode
}

#[no_mangle]
pub extern "efiapi" fn efi_main(_: Cptr, svc: &mut &mut PeiServices) -> EfiStatus {
    uart::init();
    info!("loaded PigPEI");

    // ACPI sleep states will preserve memory but clear various CPU states.
    if matches!(get_boot_mode(svc), BootMode::S2Resume | BootMode::S3Resume |
                                    BootMode::S4Resume | BootMode::S5Resume) {
        return EfiStatus::Success
    }

    // Register callback to hook DXE core and service tables.
    unsafe { dxe::hook_dxe_core(svc).expect("failed to hook DXE core") };
    EfiStatus::Success
}
