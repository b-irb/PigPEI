use core::fmt::Write;
use core::ffi;
use crate::efi::{
    BootServices,
    EfiResult,
    EfiStatus,
    Guid,
    HobGenericHeader,
    HobHandoffInfoTable,
    MemoryAllocationModule,
    PeiServices,
    PpiDescriptor,
};

static mut ORIGINAL_INSTALL_PPI:
    extern "efiapi" fn (&mut &mut PeiServices, *const PpiDescriptor)
        -> EfiStatus = install_ppi_hook; // Placeholder to make it compile.

pub fn hook_dxe_core(svc: &mut &mut PeiServices) -> Result<(), EfiStatus> {
    // DXE core is mapped into the PAS of the EFI_DXE_IPL_PPI PEIM then called.

    unsafe {
        ORIGINAL_INSTALL_PPI = svc.install_ppi;
    };
    // Hook the InstallPpi PEI service entry to trigger execution after DXE
    // core has been mapped but has not been called.
    debug!("hooking InstallPpi in EFI_PEI_SERVICES");
    svc.install_ppi = install_ppi_hook;

    Ok(())
}

unsafe fn find_dxe_core_hob(svc: &mut &mut PeiServices)
        -> EfiResult<*const MemoryAllocationModule> {
    // Retrieve the final HOB list for all PEIMs.
    let mut hob_list: *const HobGenericHeader = core::ptr::null();
    let status = (svc.get_hob_list)(svc, &mut hob_list);
    if status != EfiStatus::Success {
        error!("unable to call GetHobList service: {:?}", status);
        return Err(status);
    }

    const EFI_HOB_MEMORY_ALLOCATION_HOB: u16 = 0x0002;
    const HOB_MEMORY_ALLOC_MODULE_GUID: Guid = Guid::new(
        0xf8e21975, 0x899, 0x4f58,
        [0xa4, 0xbe, 0x55, 0x25, 0xa9, 0xc6, 0xd7, 0x7a],
    );

    // MkePkg DXE core file GUID.
    const DXE_CORE_GUID: Guid = Guid::new(
        3600993151, 0x6a18, 0x4e2f,
        [0xb4, 0x3b, 0x99, 0x20, 0xa7, 0x33, 0x70, 0xa]
    );

    info!("searching for {} HOB", DXE_CORE_GUID);

    // Iterate over the HOBs until we find the corresponding DXE core HOB.
    // The first HOB is the PHIT which contains the PA of the lsat HOB.
    let phit = hob_list.cast::<HobHandoffInfoTable>().as_ref().unwrap();
    let end_paddr = phit.end_of_hob_list;
    hob_list = hob_list.byte_add(phit.header.hob_length.into());

    // Iterate over the remaining HOBs until we find our target (or list ends).
    while hob_list != end_paddr {
        debug!("current HOB: {:p} ({:p})", hob_list, end_paddr);
        // C guarantees the first field of a struct is at first address.
        if (*hob_list).hob_type == EFI_HOB_MEMORY_ALLOCATION_HOB {
            let alloc_hob = hob_list.cast::<MemoryAllocationModule>();
            // The allocation HOBs are distinguished by a GUID in a header.
            if (*alloc_hob).alloc_header.name == HOB_MEMORY_ALLOC_MODULE_GUID {
                if (*alloc_hob).module_name == DXE_CORE_GUID {
                    info!("found DXE core HOB at {:p}", hob_list);
                    return Ok(alloc_hob);
                }
            }
        }
        hob_list = hob_list.byte_add((*hob_list).hob_length.into());
    }
    Err(EfiStatus::NotFound)
}

fn insert_boot_services_hooks(bs: &mut BootServices) -> EfiResult<()> {
    // Insert hook into GetVariable();
    // Insert hook into ExitBootServices();
    Ok(())
}

fn find_and_hook_boot_services(svc: &mut &mut PeiServices) -> EfiResult<()> {
    // DxeCore is mapped into the current PAS so we should be able to scan the
    // address space to find EFI_BOOT_SERVICES. The table is not filled out
    // during execution (unlike EFI_RUNTIME_SERVICES) so we can hook it.

    // EFI_BOOT_SERVICES starts with EFI_BOOT_SERVICES_SIGNATURE which we can
    // scan for to find the rest of the table (the table should be aligned).
    const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x56524553544f4f42;

    // The DXE core has an associated EFI_HOB_MEMORY_ALLOCATION_MODULE HOB
    // which describes the loaded PE32's memory range.
    let mut boot_services = core::ptr::null_mut();

    unsafe {
        let hob = find_dxe_core_hob(svc)?.as_ref().unwrap();

        // Scan the loaded file memory range for the BT signature.
        let base_addr = hob.alloc_header.memory_base_address;
        let max_addr  = base_addr.add(hob.alloc_header.memory_length as usize);

        info!("scanning address range {:p}-{:p}", base_addr, max_addr);

        let mut addr = core::mem::transmute::<_, *mut ffi::c_void>(base_addr);
        while addr as *const _ != max_addr {
            let candidate = addr.cast::<u64>().read();
            if candidate == EFI_BOOT_SERVICES_SIGNATURE {
                info!("found EFI_BOOT_SERVICES at {:p}", addr);
                boot_services = addr.cast::<BootServices>();
                break
            }
            addr = addr.add(core::mem::size_of::<u64>());
        }
    }

    if let Some(bs) = unsafe { boot_services.as_mut() } {
        // Insert the hooks into EFI_BOOT_SERVICES
        insert_boot_services_hooks(bs)
    } else {
        Err(EfiStatus::NotFound)
    }
}

extern "efiapi" fn install_ppi_hook(
        svc: &mut &mut PeiServices,
        mut ppi_list: *const PpiDescriptor) -> EfiStatus {
    // DxeCore loader installs EFI_PEI_END_OF_PEI_PPI to signal end of PEI.
    const PPI_DESCRIPTOR_TERMINATE_LIST: usize = 0x80000000;
    const PEI_END_OF_PEI_PPI: Guid = Guid::new(
        0x605ea650, 0xc65c, 0x42e1,
        [0xba, 0x80, 0x91, 0xa5, 0x2a, 0xb6, 0x18, 0xc6]
    );

    unsafe {
        loop {
            let descriptor = &*ppi_list;

            // Check and hook if the PPI is EFI_END_OF_PEI_PPI.
            if *descriptor.guid == PEI_END_OF_PEI_PPI {
                info!("trapped DxeLoadCore before DxeCore is called");
                // Locate and modify EFI_BOOT_SERVICES.
                if let Err(status) = find_and_hook_boot_services(svc) {
                    error!("failed to hook EFI_BOOT_SERVICES: {:?}", status);
                    // Continue execution since the system is still stable.
                }
            }

            // Install PPI using original InstallPpi service.
            let status = ORIGINAL_INSTALL_PPI(svc, ppi_list);
            if status != EfiStatus::Success {
                warn!("original InstallPpi returned {:?}", status);
                break status;
            }

            // Advance the pointer to the next entry.
            ppi_list = ppi_list.add(1);

            // The final entry of the PpiList is tagged.
            if descriptor.flags & PPI_DESCRIPTOR_TERMINATE_LIST != 0 {
                break EfiStatus::Success;
            }
        }
    }
}
