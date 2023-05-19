use crate::Cptr;
use crate::efi::{Guid, EfiStatus, TableHeader};

pub type PeiServicesPtr<'a> = &'a &'a mut PeiServices;

#[macro_export]
macro_rules! pei_fn {
    ($arg1:ty $(,$args:ty)*) => {
        extern "efiapi" fn(&&mut PeiServices, $arg1 $(,$args)*) -> EfiStatus
    };
}

#[repr(C)]
pub struct PeiServices {
    header: TableHeader,

    // PPI Functions
    pub install_ppi: pei_fn!(*const PpiDescriptor),
    reinstall_ppi: Cptr,
    locate_ppi: Cptr,
    notify_ppi: Cptr,

    // Boot Mode Functions
    pub get_boot_mode: pei_fn!(&mut BootMode),
    set_boot_mode: Cptr,

    // HOB Functions
    pub get_hob_list: pei_fn!(&mut *const HobGenericHeader),
    create_hob: Cptr,

    // Firmware Volume Functions
    ffs_find_next_volume: Cptr,
    ffs_find_next_file: Cptr,
    ffs_find_section_data: Cptr,

    // PEI Memory Functions
    install_pei_memory: Cptr,
    allocate_pages: Cptr,
    allocate_pool: Cptr,
    copy_mem: Cptr,
    set_mem: Cptr,

    // Status Code
    report_status_code: Cptr,

    // Reset
    reset_system: Cptr,

    // PEIM Published Interfaces
    //
    // I/O Abstractions
    cpu_io: Cptr,
    pci_cfg: Cptr,

    // Additional File System Services
    ffs_find_file_by_name: Cptr,
    ffs_get_file_info: Cptr,
    ffs_get_volume_info: Cptr,
    register_for_shadow: Cptr,

    find_section_data3: Cptr,
    ffs_get_file_info2: Cptr,
    reset_system2: Cptr
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BootMode {
    // Basic S0 boot path is FullConfiguration.
    FullConfig = 0x0,
    MinimalConfig = 0x1,
    NoConfigChanges = 0x02,
    FullConfigPlusDiagnostics = 0x03,
    DefaultSettings = 0x04,
    S4Resume = 0x05,
    S5Resume = 0x06,
    MfgModeSettings = 0x07,
    S2Resume = 0x10,
    S3Resume = 0x11,
    FlashUpdate = 0x12,
    RecoveryMode = 0x20,
}

#[repr(C)]
pub struct PpiDescriptor {
    pub flags: usize,
    pub guid: *const Guid,
    pub ppi: Cptr,
}

#[allow(dead_code)]
#[repr(u32)]
pub enum MemoryType {
    BootServicesCode,
    BootServicesData,
    RuntimeServicesCode,
    RuntimeServicesData,
    ConventionalMemory,
}

#[repr(C)]
pub struct HobGenericHeader {
    pub hob_type: u16,
    pub hob_length: u16,
    reserved: u32,
}

#[repr(C)]
pub struct HobHandoffInfoTable {
    pub header: HobGenericHeader,
    pub version: u32,
    pub boot_mode: BootMode,
    pub mem_hi: Cptr,
    pub mem_lo: Cptr,
    pub free_mem_hi: Cptr,
    pub free_mem_lo: Cptr,
    pub end_of_hob_list: *const HobGenericHeader,
}

#[repr(C)]
pub struct MemoryAllocationHeader {
    pub name: Guid,
    pub memory_base_address: Cptr,
    pub memory_length: u64,
    pub memory_type: MemoryType,
    reserved: [u8; 4],
}

#[repr(C)]
pub struct MemoryAllocationModule {
    pub header: HobGenericHeader,
    pub alloc_header: MemoryAllocationHeader,
    pub module_name: Guid,
    pub entrypoint: Cptr,
}
