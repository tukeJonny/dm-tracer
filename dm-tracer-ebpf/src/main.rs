#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid,
        bpf_get_current_comm,
        bpf_probe_read_user,
    },
    macros::{tracepoint, map},
    maps::{Array,PerfEventArray, HashMap},
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, info, warn, error};
use dm_tracer_common::{
    event::Event,
    dm_ioctl::dm_ioctl,
    dm_ioctl_commands::DmIoctlCommand,
};

// ioctlのID管理をするアトミックカウンタ
// 要素数１のArrayで管理する
#[map(name = "EVENT_ID")]
static mut EVENT_ID: Array<u64> = Array::with_max_entries(1, 0);

unsafe fn issue_event_id() -> Result<u64, u32> {
    let current = EVENT_ID.get_ptr_mut(0).ok_or(1u32)?;
    *current = *current.wrapping_add(1);
    Ok(*current)
}

// FIXME: アクセス競合によるパフォーマンスペナルティが大きい
#[map(name = "INFLIGHT_EVENTS")]
static mut INFLIGHT_EVENTS: HashMap<u64, Event> = HashMap::with_max_entries(1024, 0);

#[map(name = "PID_TO_ID")]
static mut PID_TO_ID: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

// https://elixir.bootlin.com/linux/v6.12.1/source/include/uapi/linux/dm-ioctl.h#L263
// dm_ioctlのデバイスタイプ値
const DM_IOCTL: u32 = 0xfd;

#[tracepoint]
pub fn trace_sys_enter_ioctl(ctx: TracePointContext) -> u32 {
    match try_trace_sys_enter_ioctl(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/*
name: sys_enter_ioctl
ID: 822
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned int fd;  offset:16;      size:8; signed:0;
        field:unsigned int cmd; offset:24;      size:8; signed:0;
        field:unsigned long arg;        offset:32;      size:8; signed:0;

print fmt: "fd: 0x%08lx, cmd: 0x%08lx, arg: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->cmd)), ((unsigned long)(REC->arg))
*/
fn try_trace_sys_enter_ioctl(ctx: TracePointContext) -> Result<u32, u32> {
    const CMD_OFFSET: usize = 24;
    let cmd: u64 = unsafe { 
        match ctx.read_at(CMD_OFFSET) {
            Ok(cmd) => cmd,
            Err(n) => return Err(n as u32),
        }
    };
    let device_type: u32 = ((cmd >> 8) & 0xff).try_into().unwrap();
    if device_type != DM_IOCTL {
        return Err(device_type as u32);
    }
    let command_number: u32 = (cmd & 0xff).try_into().unwrap();

    const ARG_OFFSET: usize = 32;
    let arg: u64 = unsafe {
        match ctx.read_at(ARG_OFFSET) {
            Ok(arg) => arg,
            Err(n) => return Err(n as u32),
        }
    };
    let dm_ctl = unsafe {
        match bpf_probe_read_user(arg as *const dm_ioctl) {
            Ok(data) => data,
            Err(n) => return Err(n as u32),
        }
    };

    let event_id = unsafe { issue_event_id()? };
    let pid = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().unwrap();
    let Some(cmd) = DmIoctlCommand::from_u32(command_number as u32) else { return Err(command_number as u32) };
    let event = Event::new(event_id, pid, comm, cmd);

    unsafe {
        INFLIGHT_EVENTS.insert(&event_id, &event, 0).unwrap();
        PID_TO_ID.insert(&pid, &event_id, 0).unwrap();
    }

    info!(&ctx, "[{}] tracepoint sys_enter_ioctl called", command_number);
    if let Some(command) = DmIoctlCommand::from_u32(command_number as u32) {
        match command {
            DmIoctlCommand::DmVersionCmd => info!(&ctx, "DM_VERSION: {}", dm_ctl.version[0]),
            DmIoctlCommand::DmTableLoadCmd | DmIoctlCommand::DmTableStatusCmd => {
                info!(&ctx, "DM_TABLE");
            }
            DmIoctlCommand::DmTargetMsgCmd => {
                info!(&ctx, "DM_TARGET_MSG");
            }
            DmIoctlCommand::DmTableDepsCmd => {
                info!(&ctx, "DM_TABLE_DEPS");
            }
            DmIoctlCommand::DmDevCreateCmd | DmIoctlCommand::DmDevRemoveCmd => {
                info!(&ctx, "DM_DEV");
            }
            DmIoctlCommand::DmListDevicesCmd => {
                info!(&ctx, "DM_LIST_DEVICES");
            }
            _ => {
                info!(&ctx, "unexpected command number: {}", command_number);
            }
        }
    }

    info!(&ctx, "sys_enter_ioctl");
    Ok(0)
}

#[tracepoint]
pub fn trace_sys_exit_ioctl(ctx: TracePointContext) -> u32 {
    match try_trace_sys_exit_ioctl(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// pid, comm => eventのマップはあってもいいかも？

/*
name: sys_exit_ioctl
ID: 821
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret
*/
fn try_trace_sys_exit_ioctl(ctx: TracePointContext) -> Result<u32, u32> {
    const RET_OFFSET: usize = 16;
    let ret: u64 = unsafe {
        match ctx.read_at(RET_OFFSET) {
            Ok(ret) => ret,
            Err(n) => return Err(n as u32),
        }
    };

    let pid = bpf_get_current_pid_tgid();
    let event_id = unsafe {
        match PID_TO_ID.get(&pid) {
            Some(id) => *id,
            None => return Err(1),
        }
    };

    unsafe {
        INFLIGHT_EVENTS.remove(&event_id).unwrap();
        PID_TO_ID.remove(&pid).unwrap();
    }

    info!(&ctx, "tracepoint sys_exit_ioctl called: {}", ret);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
