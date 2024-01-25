use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::{Cidr, Item};

#[derive(Clone, Default)]
pub struct ArrayRoutingTable {
    inner: Vec<Item>,
}

impl ArrayRoutingTable {
    pub fn add(&mut self, item: Item) {
        let index = self.inner
            .iter()
            .position(|v| v.cidr.prefix_len < item.cidr.prefix_len);

        match index {
            None => self.inner.push(item),
            Some(i) => self.inner.insert(i, item)
        };
    }

    pub fn remove(&mut self, cidr: &Cidr) -> Option<Item> {
        let index = self.inner
            .iter()
            .position(|v| v.cidr == *cidr);

        index.map(|index| self.inner.remove(index))
    }

    pub fn find(&self, _src: Ipv4Addr, to: Ipv4Addr) -> Option<&Item> {
        self.inner
            .iter()
            .find(|v| Ipv4Net::from(v.cidr).contains(&to))
    }
}