use core::fmt::{Write, Result};
use crate::asm::{inb, outb};

const COM1: u16 = 0x3f8;

// DLAB = 0
const REG_DAT: u16 = COM1 + 0;
const REG_IER: u16 = COM1 + 1;
// DLAB = 1
const REG_BLS: u16 = COM1 + 0;
const REG_BMS: u16 = COM1 + 1;

const REG_CTR: u16 = COM1 + 2;
const REG_LCR: u16 = COM1 + 3;
const REG_LSR: u16 = COM1 + 5;

pub fn init() {
    // 38400 baud rate
    let divisor: u16 = 3;

    unsafe {
        outb(REG_IER, 0x00); // disable interrupts
        outb(REG_LCR, 0x80); // enable baud divisor registers
        outb(REG_BLS, (divisor & 0xff) as u8);
        outb(REG_BMS, (divisor >> 0x8) as u8);
        // disable baud divisor registers
        outb(REG_LCR, 0x03); // 1N8
        outb(REG_CTR, 0x00); // disable FIFO
    }
}

pub fn write(buf: &[u8]) {
    // bit indicates whether the transmission buffer is empty
    const THER: u8 = 0x20;

    for &byte in buf.iter() {
        unsafe {
            // spin until the byte is consumed by a receiver
            while inb(REG_LSR) & THER == 0 {}
            outb(REG_DAT, byte);
        }
    }
}

pub struct UartWrapper{}

impl Write for UartWrapper {
    fn write_str(&mut self, s: &str) -> Result {
        write(s.as_bytes());
        Ok(())
    }
}
