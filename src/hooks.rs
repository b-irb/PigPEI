use crate::efi::{
    Guid,
    BootServices,
    RuntimeServices,
    SystemTable,
    EfiResult,
    EfiStatus,
};
use core::{mem::MaybeUninit, fmt::Write, ffi::c_void};
use crate::Cptr;
use macros::guid;

pub unsafe fn install_dxe_hooks(
    st: &mut SystemTable,
    bs: &mut BootServices,
    rt: &'static mut RuntimeServices) -> EfiResult<()> {

    RT.write(rt);

    info!("hooking gBS->RegisterProtocolNotify");
    ORIG_REG_PROTO_NOTIFY = bs.register_protocol_notify;
    bs.register_protocol_notify = reg_proto_notify_hook;

    Ok(())
}

static mut RT: MaybeUninit<&mut RuntimeServices> = MaybeUninit::<_>::uninit();

static mut EXIT_BOOT_SERVICES: extern "efiapi" fn(Cptr, usize) -> EfiStatus
    = exit_boot_services_hook;

static mut ORIG_RT_GET_VARIABLE:
    os_fn!(*const u16, *const Guid, *mut u32, *mut usize, *mut c_void)
    = rt_get_variable_hook;

static mut ORIG_REG_PROTO_NOTIFY:
    dxe_fn!(*const Guid, Cptr, Cptr) = reg_proto_notify_hook;

extern "efiapi" fn reg_proto_notify_hook(
    guid: *const Guid, event: Cptr, reg: Cptr) -> EfiStatus {
    const FIRMWARE_VOLUME_2_PROTOCOL_GUID: Guid
        = guid!("220e73b6-6bdb-4413-8405b974b108619a");

    if unsafe { *guid } == FIRMWARE_VOLUME_2_PROTOCOL_GUID {
        info!("intercepted DxeMain after initialisation");
        // Lazy hooking after gRT has been initialised (this is super ugly).
        unsafe {
            ORIG_RT_GET_VARIABLE = (*RT.as_ptr()).get_variable;
            (*RT.as_mut_ptr()).get_variable = rt_get_variable_hook;
        }
    }
    unsafe { ORIG_REG_PROTO_NOTIFY(guid, event, reg) }
}

extern "efiapi" fn rt_get_variable_hook(
    svc: &RuntimeServices,
    name: *const u16,
    guid: *const Guid,
    attr: *mut u32,
    size: *mut usize,
    data: *mut c_void) -> EfiStatus {
    info!("hooked gRT->GetVariable()");
    unsafe { ORIG_RT_GET_VARIABLE(svc, name, guid, attr, size, data) }
}

extern "efiapi" fn exit_boot_services_hook(c: Cptr, key: usize) -> EfiStatus {
    info!("hooked ExitBootServices()");
    unsafe { EXIT_BOOT_SERVICES(c, key) }
}
