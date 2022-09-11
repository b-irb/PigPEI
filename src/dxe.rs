use crate::efi::{PeiServices, EfiStatus};

pub fn launch_dxe_core(svc: &&PeiServices) -> Result<(), EfiStatus> {
    Ok(())
}
