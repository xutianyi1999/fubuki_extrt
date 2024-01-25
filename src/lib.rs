use std::ffi::c_char;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use arc_swap::ArcSwap;
use ipnet::Ipv4Net;
use crate::arrayrt::ArrayRoutingTable;

mod arrayrt;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ItemKind {
    VirtualRange,
    IpsRoute,
    AllowedIpsRoute,
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Cidr {
    addr: u32,
    prefix_len: u8,
}

impl From<Cidr> for Ipv4Net {
    fn from(value: Cidr) -> Self {
        Ipv4Net::new(Ipv4Addr::from(value.addr), value.prefix_len).unwrap()
    }
}

impl From<Ipv4Net> for Cidr {
    fn from(value: Ipv4Net) -> Self {
        Cidr {
            addr: u32::from(value.addr()),
            prefix_len: value.prefix_len(),
        }
    }
}

#[repr(C)]
pub struct OptionC<T> {
    is_some: bool,
    value: MaybeUninit<T>,
}

impl<T: Copy> Clone for OptionC<T> {
    fn clone(&self) -> Self {
        OptionC {
            is_some: self.is_some,
            value: self.value.clone(),
        }
    }
}

impl<T> From<OptionC<T>> for Option<T> {
    fn from(value: OptionC<T>) -> Self {
        if value.is_some {
            Some(unsafe { value.value.assume_init() })
        } else {
            None
        }
    }
}

impl<T> From<Option<T>> for OptionC<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            None => OptionC {
                is_some: false,
                value: MaybeUninit::uninit(),
            },
            Some(v) => OptionC {
                is_some: true,
                value: MaybeUninit::new(v),
            }
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct Extend {
    item_kind: OptionC<ItemKind>,
}

#[repr(C)]
#[derive(Clone)]
pub struct Item {
    cidr: Cidr,
    gateway: u32,
    interface_index: usize,
    extend: Extend,
}
type InterfaceInfoFn = extern "C" fn(ctx: &Context, info_json: *mut c_char);

pub struct RoutingTable<'a> {
    imp: ArcSwap<ArrayRoutingTable>,
    _fubuki_ctx: &'a Context,
    _interface_info_fn: InterfaceInfoFn,
}

pub struct Context {}

#[no_mangle]
pub extern "C" fn create_routing_table(
    ctx: &Context,
    interface_info_fn: InterfaceInfoFn,
) -> *mut RoutingTable {
    let rt = RoutingTable {
        imp: ArcSwap::from_pointee(ArrayRoutingTable::default()),
        _fubuki_ctx: ctx,
        _interface_info_fn: interface_info_fn,
    };
    Box::into_raw(Box::new(rt))
}

#[no_mangle]
pub extern "C" fn add_route(
    table: &RoutingTable,
    item: Item,
) {
    table.imp.rcu(|t| {
        let mut t = (**t).clone();
        t.add(item.clone());
        t
    });
}

#[no_mangle]
pub extern "C" fn remove_route(
    table: &RoutingTable,
    cidr: &Cidr,
) -> OptionC<Item> {
    let mut ret = None;

    table.imp.rcu(|t| {
        let mut t = (**t).clone();
        ret = t.remove(cidr);
        t
    });

    OptionC::from(ret)
}

#[no_mangle]
pub extern "C" fn find_route<'a>(
    table: &'a RoutingTable<'a>,
    src: u32,
    to: u32,
) -> OptionC<Item> {
    let guard = table.imp.load();
    let ret = guard.find(Ipv4Addr::from(src), Ipv4Addr::from(to));
    OptionC::from(ret.cloned())
}

#[no_mangle]
pub extern "C" fn drop_routing_table(
    table: *mut RoutingTable,
) {
    let _ = unsafe { Box::from_raw(table) };
}