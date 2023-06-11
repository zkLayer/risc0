#[derive(Clone)]
/// A host-side implementation of a system call.
pub trait Syscall {
    /// Invokes the system call.
    fn syscall(
        &mut self,
        syscall: &str,
        ctx: &mut dyn SyscallContext,
        to_guest: &mut [u32],
    ) -> Result<(u32, u32)>;
}

/// Access to memory and machine state for syscalls.
pub trait SyscallContext : MemoryState{
    /// Returns the current cycle being executed.
    fn get_cycle(&self) -> usize;

    /// Loads the value of the given register, e.g. REG_A0.
    fn load_register(&mut self, num: usize) -> u32 {
        self.load_u32((SYSTEM.start() + num * WORD_SIZE) as u32)
    }

    /// Loads bytes from the given region of memory.
    fn load_region(&mut self, addr: u32, size: u32) -> Vec<u8> {
        let mut region = Vec::new();
        for addr in addr..addr + size {
            region.push(self.load_u8(addr));
        }
        region
    }

    /// Loads an individual word from memory.
    fn load_u32(&mut self, addr: u32) -> u32;

    /// Loads an individual byte from memory.
    fn load_u8(&mut self, addr: u32) -> u8;

    /// Loads a null-terminated string from memory.
    fn load_string(&mut self, mut addr: u32) -> Result<String> {
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
}


/// A table of system calls, dispatched by name.
pub(crate) struct SyscallTable<'a> {
    pub(crate) inner: HashMap<String, Rc<RefCell<dyn Syscall + 'a>>>,
}

impl<'a> Default for SyscallTable<'a> {
    fn default() -> Self {
        let mut new = Self {
            inner: Default::default(),
        };
        new.with_syscall(SYS_CYCLE_COUNT, syscalls::CycleCount)
            .with_syscall(SYS_LOG, syscalls::Log)
            .with_syscall(SYS_PANIC, syscalls::Panic);
        new
    }
}

impl<'a> SyscallTable<'a> {
    pub fn with_syscall(&mut self, syscall: SyscallName, handler: impl Syscall + 'a) -> &mut Self {
        self.inner
            .insert(syscall.as_str().to_string(), Rc::new(RefCell::new(handler)));
        self
    }
}

impl<'a> Syscall for SyscallTable<'a> {
    fn syscall(
        &mut self,
        syscall: &str,
        ctx: &mut dyn SyscallContext,
        to_guest: &mut [u32],
    ) -> Result<(u32, u32)> {
        if let Some(handler) = self.inner.get(syscall) {
            (*handler).borrow_mut().syscall(syscall)
        } else {
            bail!("Unknown system call {syscall}")
        }
    }
}

pub(crate) mod syscalls {
    use std::{cmp::min, collections::HashMap, str::from_utf8};

    use anyhow::{bail, Result};
    use risc0_zkvm_platform::{
        syscall::reg_abi::{REG_A3, REG_A4},
        WORD_SIZE,
    };

    use super::{Syscall, SyscallContext};

    pub(crate) struct CycleCount;
    impl Syscall for CycleCount {
        fn syscall(
            &mut self,
            _syscall: &str,
            ctx: &mut dyn SyscallContext,
            _to_guest: &mut [u32],
        ) -> Result<(u32, u32)> {
            Ok((ctx.get_cycle() as u32, 0))
        }
    }

    pub(crate) struct Getenv(pub HashMap<String, String>);
    impl Syscall for Getenv {
        fn syscall(
            &mut self,
            _syscall: &str,
            ctx: &mut dyn SyscallContext,
            to_guest: &mut [u32],
        ) -> Result<(u32, u32)> {
            let buf_ptr = ctx.load_register(REG_A3);
            let buf_len = ctx.load_register(REG_A4);
            let from_guest = ctx.load_region(buf_ptr, buf_len);
            let msg = from_utf8(&from_guest)?;

            match self.0.get(msg) {
                None => Ok((u32::MAX, 0)),
                Some(val) => {
                    let nbytes = min(to_guest.len() * WORD_SIZE, val.as_bytes().len());
                    let to_guest_u8s: &mut [u8] = bytemuck::cast_slice_mut(to_guest);
                    to_guest_u8s[0..nbytes].clone_from_slice(&val.as_bytes()[0..nbytes]);
                    Ok((val.as_bytes().len() as u32, 0))
                }
            }
        }
    }

    pub(crate) struct Log;
    impl Syscall for Log {
        fn syscall(
            &mut self,
            _syscall: &str,
            ctx: &mut dyn SyscallContext,
            _to_guest: &mut [u32],
        ) -> Result<(u32, u32)> {
            let buf_ptr = ctx.load_register(REG_A3);
            let buf_len = ctx.load_register(REG_A4);
            let from_guest = ctx.load_region(buf_ptr, buf_len);
            let msg = from_utf8(&from_guest)?;
            println!("R0VM[{}] {}", ctx.get_cycle(), msg);
            Ok((0, 0))
        }
    }

    pub(crate) struct Panic;
    impl Syscall for Panic {
        fn syscall(
            &mut self,
            _syscall: &str,
            ctx: &mut dyn SyscallContext,
            _to_guest: &mut [u32],
        ) -> Result<(u32, u32)> {
            let buf_ptr = ctx.load_register(REG_A3);
            let buf_len = ctx.load_register(REG_A4);
            let from_guest = ctx.load_region(buf_ptr, buf_len);
            let msg = from_utf8(&from_guest)?;
            bail!("Guest panicked: {msg}");
        }
    }
}

impl<'a> Default for PosixIo<'a> {
    fn default() -> Self {
        let mut new = Self {
            read_fds: Default::default(),
            write_fds: Default::default(),
        };
        new.with_read_fd(fileno::STDIN, BufReader::new(stdin()))
            .with_write_fd(fileno::STDOUT, stdout())
            .with_write_fd(fileno::STDERR, stderr());
        new
    }
}

impl<'a> Syscall for PosixIo<'a> {
    fn syscall(
        &mut self,
        syscall: &str,
        ctx: &mut dyn SyscallContext,
        to_guest: &mut [u32],
    ) -> Result<(u32, u32)> {
        // TODO: Is there a way to use "match" here instead of if statements?
        if syscall == SYS_READ_AVAIL.as_str() {
            self.sys_read_avail(ctx)
        } else if syscall == SYS_READ.as_str() {
            self.sys_read(ctx, to_guest)
        } else if syscall == SYS_WRITE.as_str() {
            self.sys_write(ctx)
        } else {
            bail!("Unknown syscall {syscall}")
        }
    }
}
impl<'a> Syscall for Rc<RefCell<PosixIo<'a>>> {
    fn syscall(
        &mut self,
        syscall: &str,
        ctx: &mut dyn SyscallContext,
        to_guest: &mut [u32],
    ) -> Result<(u32, u32)> {
        self.borrow_mut().syscall(syscall, ctx, to_guest)
    }
}
