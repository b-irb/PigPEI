#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![feature(panic_info_message)]

use core::fmt::Write;
use core::panic::PanicInfo;
use core::ffi;

mod efi;
mod asm;
mod uart;
#[macro_use]
mod log;
mod dxe;

use asm::{outb, cli, hlt};
use efi::{EfiStatus, PeiServices, BootMode};

type Cptr = *const ffi::c_void;

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    // panic!() macro will provide a default message and always
    // include the invocation location.
    let message = info.message().unwrap();
    let location = info.location().unwrap();
    // Write the panic message to the console.
    error!("{} at {}", message, location);
    // Write to QEMU ISA debug exit device to exit.
    unsafe { outb(0x501, 1) };
    warn!("QEMU did not quit...");
    // HLT loop to hang processor since we could not exit.
    loop { unsafe { cli(); hlt() } }
}

fn get_boot_mode(svc: &&PeiServices) -> BootMode {
    let mut boot_mode = BootMode::FullConfig;
    if (svc.get_boot_mode)(svc, &mut boot_mode) != EfiStatus::Success {
        panic!("call to GetBootMode() failed")
    }
    boot_mode
}

#[no_mangle]
pub extern "efiapi" fn efi_main(_: Cptr, svc: &&PeiServices) -> EfiStatus {
    uart::init();
    info!("loaded PigPEI");

    // ACPI sleep states will preserve memory but clear various CPU states.
    if matches!(get_boot_mode(svc), BootMode::S2Resume | BootMode::S3Resume |
                                    BootMode::S4Resume | BootMode::S5Resume) {
        return EfiStatus::Success
    }

    // Launch DXE core to spawn DXE applications/drivers with hooked tables.
    dxe::launch_dxe_core(svc).expect("failed to launch DXE core");

    EfiStatus::Success
}
