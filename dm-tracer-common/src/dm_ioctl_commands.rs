///! ref: https://elixir.bootlin.com/linux/v6.12.1/source/include/uapi/linux/dm-ioctl.h#L235

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum DmIoctlCommand {
    /* Top level cmds */
    DmVersionCmd = 0,
    DmRemoveAllCmd = 1,
    DmListDevicesCmd = 2,
    /* device level cmds */
    DmDevCreateCmd = 3,
    DmDevRemoveCmd = 4,
    DmDevRenameCmd = 5,
    DmDevSuspendCmd = 6,
    DmDevStatusCmd = 7,
    DmDevWaitCmd = 8,
    /* Table level cmds */
    DmTableLoadCmd = 9,
    DmTableClearCmd = 10,
    DmTableDepsCmd = 11,
    DmTableStatusCmd = 12,
    /* Added later */
    DmListVersionsCmd = 13,
    DmTargetMsgCmd = 14,
    DmDevSetGeometryCmd = 15,
    DmDevArmPollCmd = 16,
    DmDevGetTargetVersionCmd = 17,
}

impl DmIoctlCommand {
    #[inline(always)]
    pub fn from_u32(value: u32) -> Option<Self> {
        if value <= 17 {
            Some(unsafe{ core::mem::transmute(value) })
        } else {
            None
        }
    }
}
