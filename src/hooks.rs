use crate::dxe::find_services;
use crate::efi::{
    Guid,
    BootServices,
    RuntimeServices,
    SystemTable,
    EfiResult,
    EfiStatus,
};
use core::{mem::MaybeUninit, fmt::Write, ffi::c_void, ptr};
use crate::Cptr;
use macros::guid;

pub unsafe fn install_dxe_hooks(
    st: &'static mut SystemTable,
    bs: &mut BootServices,
    rt: &'static mut RuntimeServices,
    phit_lo: *const u64,
    phit_hi: *const u64) -> EfiResult<()> {

    debug!("DxeMain debug gRT {:p}", rt);
    debug!("DxeMain debug gST {:p}", st);

    ST.write(st);
    RT.write(rt);
    PHIT_LO = phit_lo;
    PHIT_HI = phit_hi;

    info!("hooking gBS->RegisterProtocolNotify");
    ORIG_REG_PROTO_NOTIFY = bs.register_protocol_notify;
    bs.register_protocol_notify = reg_proto_notify_hook;

    Ok(())
}

static mut RT: MaybeUninit<&mut RuntimeServices> = MaybeUninit::<_>::uninit();
static mut ST: MaybeUninit<&mut SystemTable> = MaybeUninit::<_>::uninit();

static mut PHIT_LO: *const u64 = ptr::null();
static mut PHIT_HI: *const u64 = ptr::null();

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
        unsafe {
            let above_rt = (RT.assume_init_ref() as *const _ as *const u64).add(1);
            let mut st = *ST.assume_init_ref() as *const _;
            let mut lo = PHIT_LO;
            while st == *ST.assume_init_ref() as *const _{
                st = find_services(lo, PHIT_HI).unwrap().0;
                lo = (st as *const u64).add(1);
            }
        }
        // Lazy hooking after gRT has been initialised.
        unsafe {
            debug!("gST->Runtime {:p}", ST.assume_init_ref().runtime_services);
            info!("hooking gRT->GetVariable");
            ORIG_RT_GET_VARIABLE =  RT.assume_init_ref().get_variable;
            (&mut *RT.as_mut_ptr()).get_variable = rt_get_variable_hook;
            debug!("original {:p}", ORIG_RT_GET_VARIABLE as *const ());
            debug!("modified {:p}", &rt_get_variable_hook);
        }

        /*
         *unsafe {
         *let name = b"\xff\xfeS\x00e\x00c\x00u\x00r\x00e\x00B\x00o\x00o\x00t\x00";
         *(RT.assume_init_ref().get_variable)(RT.assume_init_ref(), name.as_ptr() as *const u16, guid, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
         *}
         */
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
