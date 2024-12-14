use crate::dm_ioctl_commands::DmIoctlCommand;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Event {
    pub id: u64,
    pub pid: u64,
    pub comm: [u8; 16],
    pub cmd: DmIoctlCommand,
}

impl Event {
    pub fn new(id: u64, pid: u64, comm: [u8;16], cmd: DmIoctlCommand) -> Self {
        Self {
            id,
            pid,
            comm,
            cmd,
        }
    }

}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
