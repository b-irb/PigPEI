use core::ffi::c_void;

pub const PEI_SPECIFICATION_MAJOR_REVISION: usize = 1;
pub const PEI_SPECIFICATION_MINOR_REVISION: usize = 10;
pub const PEI_SERVICES_SIGNATURE: u64 = 0x5652455320494550;
pub const PEI_VERSION: usize = (PEI_SPECIFICATION_MAJOR_REVISION << 17) | PEI_SPECIFICATION_MINOR_REVISION;

pub type PEIService = *const c_void;

#[repr(C)]
pub struct PEIServices {
    header: TableHeader,

    // PPI Functions
    install_ppi: PEIService,
    reinstall_ppi: PEIService,
    locate_ppi: PEIService,
    notify_ppi: PEIService,

    // Boot Mode Functions
    get_boot_mode: PEIService,
    set_boot_mode: PEIService,

    // HOB Functions
    get_hob_list: PEIService,
    create_hob: PEIService,

    // Firmware Volume Functions
    ffs_find_next_volume: PEIService,
    ffs_find_next_file: PEIService,
    ffs_find_section_data: PEIService,

    // PEI Memory Functions
    install_pei_memory: PEIService,
    allocate_pages: PEIService,
    allocate_pool: PEIService,
    copy_mem: PEIService,
    set_mem: PEIService,

    // Status Code
    report_status_code: PEIService,

    // Reset
    reset_system: PEIService,

    // PEIM Published Interfaces
    //
    // I/O Abstractions
    cpu_io: PEIService, 
    pci_cfg: PEIService,

    // Additional File System Services
    ffs_find_file_by_name: PEIService,
    ffs_get_file_info: PEIService,
    ffs_get_volume_info: PEIService,
    register_for_shadow: PEIService,

    find_section_data3: PEIService,
    ffs_get_file_info2: PEIService,
    reset_system2: PEIService
}

#[repr(usize)]
#[derive(Copy, Clone, Debug)]
pub enum BootMode {
    // Basic S0 boot path is FullConfiguration but
    // other variants are defined.
    FullConfiguration = 0x0,
    MinimalConfiguration = 0x1,
    NoConfigurationChanges = 0x02,
    FullConfigurationPlusDiagnostics = 0x03,
    DefaultSettings = 0x04,

    S4Resume = 0x05,
    S5Resume = 0x06,
    MfgModeSettings = 0x07,
    S2Resume = 0x10,
    S3Resume = 0x11,
    FlashUpdate = 0x12,
    RecoveryMode = 0x20,
}
