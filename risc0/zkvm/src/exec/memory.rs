use core::mem::take;
use std::collections::BTreeSet;

use bitvec::{bitbox, prelude::BitBox};
use num_derive::FromPrimitive;
use risc0_zkp::core::hash::sha::BLOCK_BYTES;
use risc0_zkvm_platform::memory::SYSTEM;

use crate::{binfmt::image::PageTableInfo, session::PageFaults, MemoryImage, PAGE_SIZE};

pub struct PageTable {
    info: PageTableInfo,
    bits: BitBox,
}

pub struct PagesNeeded<'a> {
    page_bits: &'a PageTable,
    page_idx: u32,
    dir: Dir,
}

impl<'a> Iterator for PagesNeeded<'a> {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.page_bits.get(self.page_idx, self.dir) {
            None
        } else {
            assert!(self.page_idx != self.page_bits.info.root_idx);
            let prev_page_idx = self.page_idx;
            self.page_idx =
                self.page_bits.info.get_page_entry_addr(self.page_idx) / PAGE_SIZE as u32;
            Some(prev_page_idx)
        }
    }
}

#[derive(FromPrimitive, Copy, Clone, Debug)]
pub enum Dir {
    Load,
    Store,
}

const DIRS: usize = 2;

impl PageTable {
    pub fn new(info: PageTableInfo, num_pages: usize) -> Self {
        Self {
            bits: bitbox![0; num_pages * DIRS],
            info: info.clone(),
        }
    }

    fn get(&self, page_idx: u32, dir: Dir) -> bool {
        *self
            .bits
            .get(page_idx as usize * DIRS + (dir as usize))
            .expect("Out of range page bit")
    }

    fn set(&mut self, page_idx: u32, dir: Dir) {
        self.bits
            .set(page_idx as usize * DIRS + (dir as usize), true)
    }

    pub fn pages_needed(&self, page_idx: u32, dir: Dir) -> impl Iterator<Item = u32> + '_ {
        PagesNeeded {
            page_bits: &self,
            page_idx,
            dir,
        }
    }

    pub fn cycles_needed(&self, page_idx: u32, dir: Dir) -> usize {
        self.pages_needed(page_idx, dir).count() * CYCLES_PER_FULL_PAGE
    }

    #[must_use]
    // Returns number of cycles needed to do all this paging
    pub fn mark_addr(&mut self, addr: u32, dir: Dir) -> usize {
        log::trace!("Marking page table for {addr:#x} dir {dir:?}");
        let page_idx = addr / PAGE_SIZE as u32;
        self.mark_page(page_idx, dir)
    }

    #[must_use]
    // Returns number of cycles needed to do all this paging
    pub fn mark_page(&mut self, mut page_idx: u32, dir: Dir) -> usize {
        let mut tot = 0;
        loop {
            if self.get(page_idx, dir) {
                return tot;
            }
            assert!(
                page_idx != self.info.root_idx,
                "mark_page assumes the root page has already been marked"
            );
            self.set(page_idx, dir);
            tot += CYCLES_PER_FULL_PAGE;
            page_idx = self.info.get_page_entry_addr(page_idx) / PAGE_SIZE as u32;
        }
    }

    pub fn clear(&mut self) {
        self.bits.fill(false)
    }

    pub fn calc_page_faults(&self) -> PageFaults {
        let mut faults: [_; DIRS] = core::array::from_fn(|_| BTreeSet::new());

        for bit in self.bits.iter_ones() {
            let dir = bit & (DIRS - 1);
            let page_idx = bit / DIRS;
            faults[dir].insert(page_idx as u32);
        }
        PageFaults {
            reads: take(&mut faults[Dir::Load as usize]),
            writes: take(&mut faults[Dir::Store as usize]),
        }
    }

    #[must_use]
    pub fn mark_root(&mut self) -> (usize, usize) {
        log::trace!(
            "Marking root of page table, index {:#x}",
            self.info.root_idx
        );
        // We assume every segment will need to read and write system
        // registers.  Since this is the case, the root page will
        // necessarily need to be updated.  However, it uses a
        // different cycle count than most pages since it might not be
        // entirely full.
        let mut read_cycles = cycles_per_page(self.info.num_root_entries as usize / 2);
        self.set(self.info.root_idx, Dir::Load);
        let mut write_cycles = cycles_per_page(self.info.num_root_entries as usize / 2);
        self.set(self.info.root_idx, Dir::Store);

        read_cycles += self.mark_addr(SYSTEM.start() as u32, Dir::Load);
        write_cycles += self.mark_addr(SYSTEM.start() as u32, Dir::Store);

        (read_cycles, write_cycles)
    }
}

pub const fn cycles_per_page(blocks_per_page: usize) -> usize {
    1 + SHA_INIT + (SHA_LOAD + SHA_MAIN) * blocks_per_page
}

/// The number of blocks that fit within a single page.
const BLOCKS_PER_PAGE: usize = PAGE_SIZE / BLOCK_BYTES;

const SHA_INIT: usize = 5;
const SHA_LOAD: usize = 16;
const SHA_MAIN: usize = 52;

pub const CYCLES_PER_FULL_PAGE: usize = cycles_per_page(BLOCKS_PER_PAGE);

pub fn image_to_ram(image: &MemoryImage, ram: &mut [u8]) {
    for (&page_idx, page) in image.pages.iter() {
        ram[page_idx as usize * PAGE_SIZE..(page_idx as usize + 1) * PAGE_SIZE]
            .clone_from_slice(page);
    }
}

pub fn ram_to_image(image: &mut MemoryImage, ram: &[u8], pages: impl Iterator<Item = u32>) {
    for page_idx in pages {
        image.store_region_in_page(
            page_idx * PAGE_SIZE as u32,
            &ram[page_idx as usize * PAGE_SIZE..(page_idx as usize + 1) * PAGE_SIZE],
        );
    }
}
