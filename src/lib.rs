use std::error::Error;
use std::ffi;
use std::mem;
use std::ops::Drop;
use std::ptr;
use std::result;

pub mod defs;
pub mod sys;

type Result<T> = result::Result<T, Box<dyn Error>>;

pub struct RtnlHandle {
    handle: sys::rtnl_handle,
}

impl RtnlHandle {
    pub fn new() -> Result<Self> {
        let mut handle = mem::MaybeUninit::<sys::rtnl_handle>::uninit();
        let err = unsafe { sys::rtnl_open(handle.as_mut_ptr(), 0) };
        if err < 0 {
            return Err("Failed to create rtnl handle".into());
        } else {
            let init_handle = unsafe { handle.assume_init() };
            Ok(RtnlHandle {
                handle: init_handle,
            })
        }
    }

    pub fn talk(&mut self, mut msg: Nlmsghdr) -> Result<()> {
        let msg_ptr = &mut msg as *mut _ as *mut sys::nlmsghdr;
        let mut null = ptr::null_mut();
        let err = unsafe { sys::rtnl_talk(self.as_cptr(), msg_ptr, &mut null as *mut _) };
        if err < 0 {
            Err("Failed to talk to NETLINK".into())
        } else {
            Ok(())
        }
    }

    fn as_cptr(&mut self) -> *mut sys::rtnl_handle {
        &mut self.handle as *mut _
    }
}

impl Drop for RtnlHandle {
    fn drop(&mut self) {
        unsafe {
            sys::rtnl_close(&mut self.handle as *mut _);
        }
    }
}

pub struct Nlmsghdr {
    data: [u8; 512],
}

impl Nlmsghdr {
    pub fn new() -> Self {
        Nlmsghdr { data: [0; 512] }
    }

    pub fn maxlen(&self) -> usize {
        self.data.len()
    }

    pub fn header(&mut self) -> &mut sys::nlmsghdr {
        unsafe { &mut *(self.as_cptr()) }
    }

    pub fn payload<T>(&mut self) -> &mut T {
        unsafe {
            let data = sys::nlmsg_data(self.as_cptr());
            &mut *(data as *mut T)
        }
    }

    pub fn addattr<T>(&mut self, type_: u32, mut data: T)
    where
        T: AttributeData,
    {
        unsafe {
            let data_ptr = data.as_mut_cptr();
            sys::addattr_l(
                self.as_cptr(),
                self.maxlen() as i32,
                type_ as i32,
                data_ptr,
                data.size(),
            );
        }
    }

    pub fn addattr_nest<F>(&mut self, type_: u32, mut func: F)
    where
        F: FnMut(&mut Nlmsghdr),
    {
        unsafe {
            let nest = sys::addattr_nest(self.as_cptr(), self.maxlen() as i32, type_ as i32);
            func(self);
            sys::addattr_nest_end(self.as_cptr(), nest);
        }
    }

    fn as_cptr(&mut self) -> *mut sys::nlmsghdr {
        self.data.as_mut_ptr() as *mut _
    }
}

pub trait AttributeData {
    fn size(&self) -> i32 {
        mem::size_of_val(self) as i32
    }

    fn as_mut_cptr(&mut self) -> *mut ffi::c_void {
        self as *mut _ as *mut ffi::c_void
    }
}

impl AttributeData for u8 {}
impl AttributeData for i8 {}
impl AttributeData for u16 {}
impl AttributeData for i16 {}
impl AttributeData for u32 {}
impl AttributeData for i32 {}
impl AttributeData for u64 {}
impl AttributeData for i64 {}

impl AttributeData for Vec<u8> {
    fn size(&self) -> i32 {
        self.len() as i32
    }

    fn as_mut_cptr(&mut self) -> *mut ffi::c_void {
        self.as_mut_ptr() as *mut ffi::c_void
    }
}

impl AttributeData for &str {
    fn size(&self) -> i32 {
        self.len() as i32
    }

    fn as_mut_cptr(&mut self) -> *mut ffi::c_void {
        let ptr = self.as_ptr();
        ptr as *mut ffi::c_void
    }
}

impl AttributeData for &[u8] {
    fn size(&self) -> i32 {
        self.len() as i32
    }

    fn as_mut_cptr(&mut self) -> *mut ffi::c_void {
        let ptr = self.as_ptr();
        ptr as *mut ffi::c_void
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple() -> Result<()> {
        let mut handle = RtnlHandle::new()?;
        let mut msg = Nlmsghdr::new();
        msg.addattr(tc::TCA_ACT_MIRRED, 10);
        msg.addattr_nest(tc::TCA_ACT_MIRRED, |msg| {
            msg.addattr(tc::TCA_ACT_MIRRED, 32)
        });
        handle.talk(msg)?;
        Ok(())
    }
}
