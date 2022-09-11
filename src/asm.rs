use core::arch::asm;

pub unsafe fn outb(port: u16, data: u8) {
    asm!("out dx, al",
         in("dx") port,
         in("al") data as u8,
         options(preserves_flags, nomem, nostack));
}

pub unsafe fn inb(port: u16) -> u8 {
    let mut _data: u8 = 0;
    asm!("in al, dx",
         in("dx") port,
         out("al") _data,
         options(preserves_flags, nomem, nostack));
    _data
}

pub unsafe fn hlt() {
    asm!("hlt", options(preserves_flags, nomem, nostack));
}

pub unsafe fn cli() {
    asm!("cli", options(preserves_flags, nomem, nostack));
}
