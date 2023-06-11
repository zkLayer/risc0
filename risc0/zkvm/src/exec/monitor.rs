// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{array};

use anyhow::Result;
use risc0_zkp::core::hash::sha::BLOCK_BYTES;
use risc0_zkvm_platform::{memory::SYSTEM, PAGE_SIZE, WORD_SIZE};
use rrs_lib::{MemAccessSize, Memory};

use super::{io::SyscallContext,   TraceEvent};
use crate::{ session::PageFaults, MemoryImage,MEM_SIZE};

/// The number of blocks that fit within a single page.
const BLOCKS_PER_PAGE: usize = PAGE_SIZE / BLOCK_BYTES;

const SHA_INIT: usize = 5;
const SHA_LOAD: usize = 16;
const SHA_MAIN: usize = 52;

const fn cycles_per_page(blocks_per_page: usize) -> usize {
    1 + SHA_INIT + (SHA_LOAD + SHA_MAIN) * blocks_per_page
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct MemStore {
    addr: u32,
    data: u8,
}

pub(crate) struct MemoryMonitor {
    pub image: MemoryImage,
    pages: Vec<PageFlags>,
    pub traces: Option<Vec<TraceEvent>>,
    pub prev_segments_cycle: usize,
}

impl<Inst: RecordMem> MemoryMonitor {
    pub fn enable_trace(&mut self) {
        self.traces = Some(Vec::new());
    }

    fn est_cycles(&self, addr: u32, dir: IncludeDir) -> usize {
        let idx = addr as usize / PAGE_SIZE;
        let page = &self.pages[idx];

        let did_page = match dir {
            IncludeDir::Read => {page.page_in},
            IncludeDir::Write => {page.page_out}
        };

        if idx as u32 == info.root_idx || did_page {
            0
        } else {
            cycles_per_page(BLOCKS_PER_PAGE) + est_cycles(self.image.info.get_page_entry_addr(idx as u32))
        }
    }

    fn include(&mut self, addr: u32, dir: IncludeDir) {
        let info = &self.image.info;
        let idx = addr as usize / PAGE_SIZE;
        debug_assert_eq!(idx , info.get_page_index(addr) as usize);
        let page = &mut self.pages[idx];

        let did_page = match dir {
            IncludeDir::Read => {&mut page.page_in},
            IncludeDir::Write => {&mut page.page_out}
        };

        if !*did_page {
            *did_page = true;

            self.segment_cycle += self.compute_page_cycles(idx as u32);

            if idx as u32 != info.root_idx {
                self.include( info.get_page_entry_addr(idx as u32), dir)
            }
        }
    }

    pub fn new(image: MemoryImage) -> Self {
        let mut pages = Vec::new();
        pages.resize_with(MEM_SIZE / PAGE_SIZE, || Default::default());
 Self {
            image,
            pages,
            traces: None,
            segment_cycle: 0,
            prev_segments_cycle: 0
        }
    }

    pub fn load_u8(&mut self, addr: u32) -> u8 {
        // let info = &self.image.info;
        // log::debug!("load_u8: 0x{addr:08x}");
        self.include( addr, IncludeDir::Read);
        let mut b = [0_u8];
        self.image.load_region_in_page(addr, &mut b);
        b[0]
    }

    pub fn load_u16(&mut self, addr: u32) -> u16 {
        assert_eq!(addr % 2, 0, "unaligned load");
        self.include( addr, IncludeDir::Read);
        let mut b = [0_u8; 2];
        self.image.load_region_in_page(addr, &mut b);
        u16::from_le_bytes(self.load_array(addr))
    }

    pub fn load_u32(&mut self, addr: u32) -> u32 {
        assert_eq!(addr % WORD_SIZE as u32, 0, "unaligned load");
        // log::debug!("load_u32: 0x{addr:08x}");
        self.include( addr, IncludeDir::Read);
        let mut b = [0_u8; 4];
        self.image.load_region_in_page(addr, &mut b);
        u32::from_le_bytes(self.load_array(addr))
    }

    pub fn load_array<const N: usize>(&mut self, addr: u32) -> [u8; N] {
        array::from_fn(|idx| self.load_u8(addr + idx as u32))
    }

    pub fn load_register(&mut self, idx: usize) -> u32 {
        self.load_u32(get_register_addr(idx))
    }

    pub fn load_registers<const N: usize>(&mut self, idxs: [usize; N]) -> [u32; N] {
        idxs.map(|idx| {
            let addr = get_register_addr(idx);
            let mut b = [0_u8; WORD_SIZE];
            self.image.load_region_in_page(addr, &mut b);
            u32::from_le_bytes(b)
        })
    }

    pub fn load_string(&mut self, mut addr: u32) -> Result<String> {
        let mut s: Vec<u8> = Vec::new();
        loop {
            let b = self.load_u8(addr);
            if b == 0 {
                break;
            }
            s.push(b);
            addr += 1;
        }
        String::from_utf8(s).map_err(anyhow::Error::msg)
    }

    fn add_trace_write(&mut self, addr: u32, value: u32) {
        if let Some(traces) = &mut self.traces {
            traces.push(TraceEvent::MemorySet {
                addr,
                value
            })
        }
    }

    pub fn store_u8(&mut self, addr: u32, data: u8) {
        self.include( addr, IncludeDir::Write);
        self.image.store_region_in_page(addr, &[data]);
        self.add_trace_write(addr, data as u32);
    }

    pub fn store_u16(&mut self, addr: u32, data: u16) {
        assert_eq!(addr % 2, 0, "unaligned store");
        self.include( addr, IncludeDir::Write);
        self.image.store_region_in_page(addr, &data.to_le_bytes());
        self.add_trace_write(addr, data as u32);
    }

    pub fn store_u32(&mut self, addr: u32, data: u32) {
        assert_eq!(addr % WORD_SIZE as u32, 0, "unaligned store");
        self.include( addr, IncludeDir::Write);
        self.image.store_region_in_page(addr, &data.to_le_bytes());
        self.add_trace_write(addr, data);
    }

    pub fn store_region(&mut self, addr: u32, slice: &[u8]) {
        slice
            .iter()
            .enumerate()
            .for_each(|(i, x)| self.store_u8(addr + i as u32, *x));
    }

    pub fn store_register(&mut self, idx: usize, data: u32) {
        self.store_region(get_register_addr(idx), &data.to_le_bytes());
    }

    fn compute_page_cycles(&self, page_idx: u32) -> usize {
        let root_idx = self.image.info.root_idx;
        let num_root_entries = self.image.info.num_root_entries as usize;
        if page_idx == root_idx {
            cycles_per_page(num_root_entries / 2)
        } else {
            cycles_per_page(BLOCKS_PER_PAGE)
        }
    }

    pub fn compute_segment_faults(&mut self) -> PageFaults {
        let mut faults = PageFaults::default();

        for (idx, page) in self.pages.iter_mut().enumerate() {
            if page.page_in {
                faults.reads.insert(idx as u32);
            }
            if page.page_out {
                faults.writes.insert(idx as u32);
            }
        }
        faults
    }

    pub fn clear_segment(&mut self) {
        for  page in self.pages.iter_mut() {
            page.page_in = false;
            page.page_out = false;
        }

        self.prev_segments_cycle += self.segment_cycle;
        self.segment_cycle = 0;
    }
}

impl<Inst: RecordMem> Memory for MemoryMonitor {
    fn read_mem(&mut self, addr: u32, size: MemAccessSize) -> Option<u32> {
        match size {
            MemAccessSize::Byte => Some(self.load_u8(addr) as u32),
            MemAccessSize::HalfWord => Some(self.load_u16(addr) as u32),
            MemAccessSize::Word => Some(self.load_u32(addr)),
        }
    }

    fn write_mem(&mut self, addr: u32, size: MemAccessSize, store_data: u32) -> bool {
        match size {
            MemAccessSize::Byte => self.store_u8(addr, store_data as u8),
            MemAccessSize::HalfWord => self.store_u16(addr, store_data as u16),
            MemAccessSize::Word => self.store_u32(addr, store_data),
        };
        true
    }
}

impl SyscallContext for MemoryMonitor {
    fn get_cycle(&self) -> usize {
        self.segment_cycle + self.prev_segments_cycle
    }

    fn load_u32(&mut self, addr: u32) -> u32 {
        MemoryMonitor::load_u32(self, addr)
    }

    fn load_u8(&mut self, addr: u32) -> u8 {
        MemoryMonitor::load_u8(self, addr)
    }
}

fn get_register_addr(idx: usize) -> u32 {
    (SYSTEM.start() + idx * WORD_SIZE) as u32
}

enum IncludeDir {
    Read,
    Write,
}

impl PageFaults {
    #[allow(dead_code)]
    fn dump(&self) {
        log::debug!("PageFaultInfo");
        log::debug!("  reads>");
        for idx in self.reads.iter().rev() {
            log::debug!("  0x{:08X}", idx);
        }
        log::debug!("  writes>");
        for idx in self.writes.iter() {
            log::debug!("  0x{:08X}", idx);
        }
    }
}

#[derive(Default,Debug)]
struct PageFlags {
    // True if this needs to be paged in this segment.
    page_in: bool,
    // True if this needs to be paged out this segment.
    page_out: bool,
}

