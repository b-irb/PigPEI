#![no_std]

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{LitStr, parse_macro_input};

#[proc_macro]
pub fn guid(args: TokenStream) -> TokenStream {
    let binding = parse_macro_input!(args as LitStr).value();
    let mut iter = binding.split('-');
    let data1 = u32::from_str_radix(iter.next().unwrap(), 16).unwrap();
    let data2 = u16::from_str_radix(iter.next().unwrap(), 16).unwrap();
    let data3 = u16::from_str_radix(iter.next().unwrap(), 16).unwrap();
    let data4 = u64::from_str_radix(iter.next().unwrap(), 16).unwrap();

    quote!(crate::efi::Guid{
        data1: #data1,
        data2: #data2,
        data3: #data3,
        data4: #data4.to_be_bytes(),
    }).into()
}
