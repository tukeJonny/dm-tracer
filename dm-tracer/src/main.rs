use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dm-tracer"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // enter
    println!("loading enter ioctl...");
    let enter_ioctl_tracer: &mut TracePoint = ebpf.program_mut("trace_sys_enter_ioctl").unwrap().try_into()?;
    enter_ioctl_tracer.load()?;
    enter_ioctl_tracer.attach("syscalls", "sys_enter_ioctl")?;
    println!("enter ioctl has loaded");

    // exit
    println!("loading exit ioctl...");
    let exit_ioctl_tracer: &mut TracePoint = ebpf.program_mut("trace_sys_exit_ioctl").unwrap().try_into()?;
    exit_ioctl_tracer.load()?;
    exit_ioctl_tracer.attach("syscalls", "sys_exit_ioctl")?;
    println!("exit ioctl has loaded");

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
