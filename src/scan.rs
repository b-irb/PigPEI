use crate::efi::{
    RuntimeServices,
    SystemTable,
};
use crate::asm::read_cr3;
use core::fmt::Write;
use core::mem::size_of;

const PAGE_SHIFT: u64 = 12;

type Pml4e = u64;
type Pdpte = u64;
type Pdte = u64;
type Pte = u64;

fn is_present(v: u64) -> bool {
    v & 1 > 0
}

fn get_pfn(e: u64) -> u64 {
    (e >> 12) & 0xfffffffff
}

fn is_exec(e: u64) -> bool {
    e & 0x8000000000000000 > 0
}

fn is_large_page(e: u64) -> bool {
    e & 0x80 > 0
}

pub unsafe fn hunt_for_tables()
        -> Option<(
            &'static mut SystemTable,
            &'static mut RuntimeServices)> {
    debug!("searching pages for table signatures");
    // UEFI is identity mapped so no physical->virtual conversion required.
    let cr3 = read_cr3();
    debug!("cr3 = {:x}", cr3);
    // Physical address of 4K aligned PML4 table.
    let pml4 = ((cr3 >> 12) << PAGE_SHIFT) as *const Pml4e;

    debug!("PML4 = {:p}", pml4);
    for pml4idx in 0..512 {
        let pml4e = *(pml4.add(pml4idx));
        let pdpt = (get_pfn(pml4e) << PAGE_SHIFT) as *const Pdpte;
        if !is_present(pml4e) { continue }
        for pdptidx in 0..512 {
            let pdpte = *(pdpt.add(pdptidx));
            let pdt = (get_pfn(pdpte) << PAGE_SHIFT) as *const Pdte;
            if !is_present(pdpte) { continue }
            if is_large_page(pdpte) && !is_exec(pdpte) {
                if let Some((st, rt)) = scan_region(pdt, 0x40000000) {
                    return Some((st, rt))
                }
                continue
            }
            for pdtidx in 0..512 {
                let pdte = *(pdt.add(pdtidx));
                let pt = (get_pfn(pdte) << PAGE_SHIFT) as *const Pte;
                if !is_present(pdte) { continue }
                if is_large_page(pdte) && !is_exec(pdte) {
                    if let Some((st, rt)) = scan_region(pt, 0x200000) {
                        return Some((st, rt))
                    }
                    continue
                }
                for ptidx in 0..512 {
                    let pte = *(pt.add(ptidx));
                    if !is_present(pte) || is_exec(pte) { continue }
                    let page = (get_pfn(pdte) << PAGE_SHIFT) as *const u64;
                    if let Some((st, rt)) = scan_region(page, 0x1000) {
                        return Some((st, rt))
                    }
                }
            }
        }
    }
    None
}

unsafe fn scan_region(mut ptr: *const u64, len: usize)
        -> Option<(
            &'static mut SystemTable,
            &'static mut RuntimeServices)> {

    const EFI_RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544e5552;
    const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453595320494249;

    // UEFI memory never going to exceed 4GB so use it as a cut-off.
    if ptr.is_null() || (ptr as u64) >= 0x100000000 {
        return None
    }
    let page_end = ptr.add(len >> 3);

    let mut st: Option<&'static mut SystemTable>  = None;
    let mut rt: Option<&'static mut RuntimeServices> = None;

    while page_end.offset_from(ptr) > size_of::<RuntimeServices>() as isize {
        ptr = ptr.add(1);
        if *ptr == EFI_SYSTEM_TABLE_SIGNATURE {
            let candidate = (ptr as *mut SystemTable).as_mut().unwrap();
            if is_st_valid(candidate) {
                info!("found EFI_SYSTEM_TABLE at {:p}", candidate);
                if let Some(rtsv) = &rt {
                    if are_st_rt_paired(candidate, rtsv) {
                        return Some((candidate, rt.unwrap()))
                    }
                }
                st = Some(candidate);
            }
        } else if *ptr == EFI_RUNTIME_SERVICES_SIGNATURE {
            let candidate = (ptr as *mut RuntimeServices).as_mut().unwrap();
            if is_rt_valid(candidate) {
                info!("found EFI_RUNTIME_SERVICES at {:p}", candidate);
                if let Some(syst) = &st {
                    if are_st_rt_paired(syst, candidate) {
                        return Some((st.unwrap(), candidate))
                    }
                }
                rt = Some(candidate);
            }
        }
    }
    None
}

fn is_st_valid(st: &SystemTable) -> bool {
    // 1MB region of UEFI is for legacy address range.
    st.runtime_services as u64 >= 0x100000 &&
        st.boot_services as u64 >= 0x100000
}

fn is_rt_valid(rt: &RuntimeServices) -> bool {
    rt.get_time as u64 >= 0x100000 &&
    rt.get_next_high_monotonic_count as u64 >= 0x100000
}

fn are_st_rt_paired(st: &SystemTable, rt: &RuntimeServices) -> bool {
    // A valid EFI_SYSTEM_TABLE refers to EFI_RUNTIME_SERVICES
    st.runtime_services as *const _ == rt as *const _
}
