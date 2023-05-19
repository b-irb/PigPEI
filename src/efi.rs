use core::ffi::c_void;
use crate::Cptr;

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl core::fmt::Display for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let data4 = u64::from_be_bytes(self.data4);
        write!(f, "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
               self.data1, self.data2, self.data3,
               data4 >> 48, data4 & 0xffffffffffff)
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EfiStatus {
    Success = 0,
    LoadError = 1,
    NotFound = 14,
}

pub type EfiResult<T> = Result<T, EfiStatus>;

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: Cptr,
}

#[macro_export]
macro_rules! dxe_fn {
    ($arg1:ty $(,$args:ty)*) => {
        extern "efiapi" fn($arg1 $(,$args)*) -> EfiStatus
    };
}

#[repr(C)]
pub struct BootServices {
    pub header: TableHeader,

    // Task Priority Services
    pub raise_tpl: Cptr,
    pub restore_tpl: Cptr,

    // Memory Services
    pub allocate_pages: Cptr,
    pub free_pages: Cptr,
    pub get_memory_map: Cptr,
    pub allocate_pool: Cptr,
    pub free_pool: Cptr,

    // Event & Timer Services
    pub create_event: extern "efiapi" fn(u32, usize, Cptr, *const Guid,
                                         *mut c_void) -> EfiStatus,
    pub set_timer: Cptr,
    pub wait_for_event: Cptr,
    pub signal_event: Cptr,
    pub close_event: Cptr,
    pub check_event: Cptr,

    // Protocol Handler Services
    pub install_protocol_interface: Cptr,
    pub reinstall_protocol_interface: Cptr,
    pub uninstall_protocol_interface: Cptr,
    pub handle_protocol: Cptr,
    pub reserved: Cptr,
    pub register_protocol_notify: dxe_fn!(*const Guid, Cptr, Cptr),
    pub locate_handle: Cptr,
    pub locate_device_path: Cptr,
    pub install_configuration_table: Cptr,

    // Image Services
    pub load_image: Cptr,
    pub start_image: Cptr,
    pub exit: Cptr,
    pub unload_image: Cptr,
    pub exit_boot_services: extern "efiapi" fn(Cptr, usize) -> EfiStatus,

    // Miscellaneous Services
    pub get_next_monotonic_count: Cptr,
    pub stall: Cptr,
    pub set_watchdog_timer: Cptr,

    // Driver Support Services
    pub connect_controller: Cptr,
    pub disconnect_controller: Cptr,
    pub open_protocol: Cptr,
    pub close_protocol: Cptr,
    pub open_protocol_information: Cptr,

    // Library Services
    pub protocol_per_handle: Cptr,
    pub locate_handle_buffer: Cptr,
    pub locate_protocol: Cptr,
    pub install_multiple_protocol_interfaces: Cptr,
    pub uninstall_multiple_protocol_interfaces: Cptr,

    // 32-bit CRC Services
    pub calculate_crc32: dxe_fn!(Cptr, usize, *mut c_void),

    // Miscellaneous Services
    pub copy_mem: Cptr,
    pub set_mem: Cptr,
    pub create_event_ex: Cptr,
}

#[macro_export]
macro_rules! os_fn {
    ($arg1:ty $(,$args:ty)*) => {
        extern "efiapi" fn(&RuntimeServices, $arg1 $(,$args)*) -> EfiStatus
    };
}

#[repr(C)]
pub struct RuntimeServices {
    pub header: TableHeader,

    // Time Services
    pub get_time: Cptr,
    pub set_time: Cptr,
    pub get_wakeup_time: Cptr,
    pub set_wakeup_time: Cptr,

    // Virtual Memory Services
    pub set_virtual_address_map: Cptr,
    pub convert_pointer: Cptr,

    // Variable Services
    pub get_variable: os_fn!(*const u16, *const Guid, *mut u32,
                             *mut usize, *mut c_void),
    pub get_next_variable_name: Cptr,
    pub set_variable: Cptr,

    // Miscellaneous Services
    pub get_next_high_monotonic_count: Cptr,
    pub reset_system: Cptr,

    // UEFI 2.0 Capsule Services
    pub update_capsule: Cptr,
    pub query_capsule_capabilities: Cptr,

    // Miscellaneous UEFI 2.0 Service
    pub query_variable_info: Cptr,
}

#[allow(dead_code)]
#[repr(C)]
pub struct SystemTable {
    pub header: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: *const u16,
    pub con_in_handle: Cptr,
    pub con_in: Cptr,
    pub con_out_handle: Cptr,
    pub con_out: Cptr,
    pub conn_err_handle: Cptr,
    pub conn_err: Cptr,
    pub runtime_services: *mut RuntimeServices,
    pub boot_services: *mut BootServices,
    pub num_table_ents: usize,
    pub config_table: *mut ConfigurationTable,
}

