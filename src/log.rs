#[allow(unused_macros)]
macro_rules! print {
    ($level:literal, $msg:literal) => {{
        writeln!($crate::uart::UartWrapper{}, "{} {}", $level, $msg).unwrap();
    }};
    ($level:literal, $msg:literal $(,$args:expr)+) => {{
        writeln!($crate::uart::UartWrapper{}, concat!("{} ", $msg),
            $level $(,$args)*).unwrap();
    }}
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! info {
    ($msg:literal $(,$args:expr)*) => {{ print!("[OK]", $msg $(,$args)*); }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! warn {
    ($msg:literal $(,$args:expr)*) => {{ print!("[??]", $msg $(,$args)*); }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! error {
    ($msg:literal $(,$args:expr)*) => {{ print!("[!!]", $msg $(,$args)*); }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! debug {
    ($msg:literal $(,$args:expr)*) => {{
        #[cfg(debug_assertions)] {
            print!("[**]", $msg $(,$args)*);
        }
    }};
}
