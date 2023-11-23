use crate::efi::{
    Guid,
    BootServices,
    RuntimeServices,
    SystemTable,
    EfiResult,
    EfiStatus,
};
use crate::scan::hunt_for_tables;
use core::{mem::MaybeUninit, fmt::Write};
use crate::Cptr;
use macros::guid;

pub unsafe fn install_dxe_hooks(
        st: &'static mut SystemTable,
        bs: &'static mut BootServices,
        rt: &'static mut RuntimeServices) -> EfiResult<()> {

    // Install a hook to trigger a scan for the new tables after they have
    // been copied to the EFI memory pool (a random page).
    info!("hooking gBS->RegisterProtocolNotify");
    ORIG_REG_PROTO_NOTIFY = bs.register_protocol_notify;
    bs.register_protocol_notify = reg_proto_notify_hook;

    BS.write(bs); // temporary, gST is copied by DxeCore!
    RT.write(rt); // temporary, gRT is copied by DxeCore!
    ST.write(st); // temporary, gST is copied by DxeCore!
    Ok(())
}

// Store the tables so we can refer to them in our hooks.
static mut BS: MaybeUninit<&mut BootServices> = MaybeUninit::<_>::uninit();
static mut RT: MaybeUninit<&mut RuntimeServices> = MaybeUninit::<_>::uninit();
static mut ST: MaybeUninit<&mut SystemTable> = MaybeUninit::<_>::uninit();

static mut ORIG_REG_PROTO_NOTIFY:
    dxe_fn!(*const Guid, Cptr, Cptr) = reg_proto_notify_hook;

static mut ORIG_EXIT_BOOT_SERVICES:
    extern "efiapi" fn(Cptr, usize) -> EfiStatus = exit_boot_services_hook;

extern "efiapi" fn reg_proto_notify_hook(
        guid: *const Guid, event: Cptr, reg: Cptr) -> EfiStatus {
    const FIRMWARE_VOLUME_2_PROTOCOL_GUID: Guid
        = guid!("220e73b6-6bdb-4413-8405b974b108619a");

    if unsafe { *guid } == FIRMWARE_VOLUME_2_PROTOCOL_GUID {
        info!("intercepted DxeMain after initialisation");
        if locate_and_hook_tables() != EfiStatus::Success {
            error!("cannot install hooks, failing silently");
        }
        info!("removing gBS->RegisterProtocolNotify hook");
        unsafe {
            BS.assume_init_mut().register_protocol_notify =
                ORIG_REG_PROTO_NOTIFY
        };
    }
    unsafe { ORIG_REG_PROTO_NOTIFY(guid, event, reg) }
}

fn locate_and_hook_tables() -> EfiStatus {
    if let Some((st, rt)) = unsafe { hunt_for_tables() } {
        info!("found referential pair of UEFI tables, all tables found");
        debug!("gST                  = {:p}", st);
        debug!("gST->RuntimeServices = {:p}", st.runtime_services);
        debug!("gST->BootServices    = {:p}", st.boot_services);
        unsafe {
            let bs = st.boot_services.as_mut().unwrap();
            info!("installing gBS->ExitBootServices hook");
            ORIG_EXIT_BOOT_SERVICES = bs.exit_boot_services;
            bs.exit_boot_services = exit_boot_services_hook;
            BS.write(bs); // permanent, this will not be relocated.
            RT.write(rt); // permanent, this will not be relocated.
            ST.write(st); // permanent, this will not be relocated.
        }
        EfiStatus::Success
    } else {
        EfiStatus::NotFound
    }
}

extern "efiapi" fn exit_boot_services_hook(img: Cptr, key: usize) -> EfiStatus {
    info!("DXE image has initiated ExitBootServices()");
    unsafe { ORIG_EXIT_BOOT_SERVICES(img, key) }
}
