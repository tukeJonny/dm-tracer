/* automatically generated by rust-bindgen 0.70.1 */

pub type __s32 = ::aya_ebpf::cty::c_int;
pub type __u32 = ::aya_ebpf::cty::c_uint;
pub type __u64 = ::aya_ebpf::cty::c_ulonglong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct dm_ioctl {
    pub version: [__u32; 3usize],
    pub data_size: __u32,
    pub data_start: __u32,
    pub target_count: __u32,
    pub open_count: __s32,
    pub flags: __u32,
    pub event_nr: __u32,
    pub padding: __u32,
    pub dev: __u64,
    pub name: [::aya_ebpf::cty::c_char; 128usize],
    pub uuid: [::aya_ebpf::cty::c_char; 129usize],
    pub data: [::aya_ebpf::cty::c_char; 7usize],
}
