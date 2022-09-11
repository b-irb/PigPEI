use core::ffi::c_void;

#[repr(C)]
pub struct EfiTableHeader {
    pub signature:   u64,
    pub revision:    u32,
    pub header_size: u32,
    pub crc32:       u32,
    pub reserved:    u32,
}

#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EfiStatus {
    Success   = 0,
    LoadError = 1,
    NotFound  = 14,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BootMode {
    FullConfig                = 0x0,
    MinimalConfig             = 0x1,
    NoConfigChanges           = 0x2,
    FullConfigPlusDiagnostics = 0x3,
    DefaultSettings           = 0x4,
    S4Resume                  = 0x5,
    S5Resume                  = 0x6,
    MfgModeSettings           = 0x7,
    S2Resume                  = 0x10,
    S3Resume                  = 0x11,
    FlashUpdate               = 0x12,
    RecoveryMode              = 0x20,
}

macro_rules! pei_fn_raw {
    ($return:ty $(,$args:ty)*) => {
        extern "efiapi" fn(&&PeiServices $(,$args)*) -> $return
    };
}

macro_rules! pei_fn {
    ($leader:ty $(,$args:ty)*) => { pei_fn_raw!(EfiStatus, $leader $(,$args)*) };
    ()                         => { pei_fn_raw!(EfiStatus) };
}

macro_rules! pei_fn2 {
    ($leader:ty $(,$args:ty)*) => { pei_fn_raw!((), $leader $(,$args)*) };
}


#[repr(C)]
pub struct PeiServices {
    pub header: EfiTableHeader,

    // PPI Services
    pub install_ppi:   pei_fn!(),
    pub reinstall_ppi: pei_fn!(),
    pub locate_ppi:    pei_fn!(&Guid, usize, *const c_void, &mut *mut c_void),
    pub notify_ppi:    pei_fn!(),

    // Boot Mode Services
    pub get_boot_mode: pei_fn!(&mut BootMode),
    pub set_boot_mode: pei_fn!(BootMode),

    // HOB Services
    pub get_hob_list: pei_fn!(&mut *mut c_void),
    pub set_hob_list: pei_fn!(u16, u16, &mut *mut c_void),

    // Firmware Volume Services
    pub ffs_find_next_volume:  pei_fn!(),
    pub ffs_find_next_file:    pei_fn!(),
    pub ffs_find_section_data: pei_fn!(),

    // PEI Memory Services
    pub install_pei_memory: pei_fn!(),
    pub allocate_pages:     pei_fn!(),
    pub allocate_pool:      pei_fn!(usize, &mut *mut [u8]),
    pub copy_mem:           pei_fn2!(*mut [u8], *mut [u8], usize),
    pub set_mem:            pei_fn2!(*mut [u8], usize, u8),

    // Status Code Services
    pub report_status_code: pei_fn!(),

    // Reset Services
    pub reset_system: pei_fn!(),

    // I/O Abstractions
    // Additional File System Related Services
}

