// Global functions
let addrof;
let read64;
let write64;
let create_fakeobj;
let read8;
let write8;
let read16;
let write16;
let read32;
let write32;
let get_backing_store;
let malloc;
let pwn;
let get_bytecode_addr;
let call_rop;
let call;
let syscall;

let sceKernelGetModuleInfoFromAddr;
let sceKernelAllocateMainDirectMemory;
let sceKernelMapNamedDirectMemory; 

let Thrd_create;
let Thrd_join;

// Global objects
let allocated_buffers = [];
let eboot_base = 0n;
let libc_base = 0n;
let libc_strerror;
let libc_error;
let return_value_addr;
let libkernel_base;
let syscall_wrapper;
let rop_chain;
let fake_bc;
let fake_frame;
let return_value_buf;
let saved_fp = 0n;

let FW_VERSION;

let SCE_KERNEL_DLSYM = 0n;

const PAGE_SIZE = 0x4000;
const PHYS_PAGE_SIZE = 0x1000;

const STDIN_FILENO = 0n;
const STDOUT_FILENO = 1n;
const STDERR_FILENO = 2n;

const AF_INET = 2n;
const AF_INET6 = 28n;
const SOCK_STREAM = 1n;
const SOCK_DGRAM = 2n;
const IPPROTO_UDP = 17n;
const IPPROTO_IPV6 = 41n;
const IPV6_PKTINFO = 46n;
const INADDR_ANY = 0n;

const SOL_SOCKET = 0xffffn;
const SO_REUSEADDR = 4n;

const PROT_NONE = 0x0n;
const PROT_READ = 0x1n;
const PROT_WRITE = 0x2n;
const PROT_EXECUTE = 0x4n;
const GPU_READ = 0x10n;
const GPU_WRITE = 0x20n;
const GPU_RW = 0x30n;

const MAP_SHARED = 0x1n;
const MAP_PRIVATE = 0x2n;
const MAP_FIXED = 0x10n;
const MAP_ANONYMOUS = 0x1000n;
const MAP_NO_COALESCE = 0x400000n;

const O_RDONLY = 0n;
const O_WRONLY = 1n;
const O_RDWR = 2n;
const O_CREAT = 0x200n;
const O_TRUNC = 0x400n;
const O_APPEND = 0x8n;
const O_NONBLOCK = 0x4n;

const SIGILL = 4n;
const SIGKILL = 9n;
const SIGBUS = 10n;
const SIGSEGV = 11n;
const SA_SIGINFO = 0x4n;

const LIBKERNEL_HANDLE = 0x2001n;

let ROP = {
    get pop_rsp()             { return eboot_base + 0x49f7fn;   },
    get pop_rax()             { return eboot_base + 0x2d954n;   },
    get pop_rdi()             { return eboot_base + 0xb0ec5n;   },
    get pop_rsi()             { return eboot_base + 0xb8a81n;   },
    get pop_rdx()             { return eboot_base + 0xb692n;    },
    get pop_rcx()             { return eboot_base + 0x187da3n;  },
    get pop_r8()              { return eboot_base + 0x1a8ff9n;  },
    get pop_r9()              { return eboot_base + 0x1394e01n; },
    get pop_rbp()             { return eboot_base + 0x69n;      },
    get mov_qword_rdi_rax()   { return eboot_base + 0x49a77n;   },
    get mov_qword_rdi_rdx()   { return eboot_base + 0x3a3b95n;  },
    get mov_rax_0x200000000() { return eboot_base + 0x1283d40n; },
    get mov_rsp_rbp()         { return eboot_base + 0xb1424n;   },
    get ret()                 { return eboot_base + 0x32n;      },
};

let DLSYM_OFFSETS = {
    "4.03": 0x317D0n,
    "4.50": 0x317D0n,
    "4.51": 0x317D0n,
    "5.00": 0x32160n,
    "5.02": 0x32160n,
    "5.10": 0x32160n,
    "5.50": 0x32230n,
    "6.00": 0x330A0n,
    "6.02": 0x330A0n,
    "6.50": 0x33110n,
    "7.00": 0x33E90n,
    "7.01": 0x33E90n,
    "7.20": 0x33ED0n,
    "7.40": 0x33ED0n,
    "7.60": 0x33ED0n,
    "7.61": 0x33ED0n,
    "8.00": 0x342E0n,
    "8.20": 0x342E0n,
    "8.40": 0x342E0n,
    "8.60": 0x342E0n,
    "9.00": 0x350E0n,
    "9.05": 0x350E0n,
    "9.20": 0x350E0n,
    "9.40": 0x350E0n,
    "9.60": 0x350E0n,
    "10.00": 0x349C0n,
    "10.01": 0x349C0n
};

let SYSCALL = {
    read: 0x3n,
    write: 0x4n,
    open: 0x5n,
    close: 0x6n,
    setuid: 0x17n,
    getuid: 0x18n,
    accept: 0x1en,
    pipe: 0x2an,
    mprotect: 0x4an,
    socket: 0x61n,
    connect: 0x62n,
    bind: 0x68n,
    setsockopt: 0x69n,
    listen: 0x6an,
    getsockopt: 0x76n,
    netgetiflist: 0x7dn,
    sendto: 0x85n,
    sysctl: 0xcan,
    nanosleep: 0xf0n,
    sigaction: 0x1a0n,
    thr_self: 0x1b0n,
    dlsym: 0x24fn,
    dynlib_load_prx: 0x252n,
    dynlib_unload_prx: 0x253n,
    randomized_path: 0x25an,
    is_in_sandbox: 0x249n,
    mmap: 0x1ddn,
    getpid: 0x14n,
    jitshm_create: 0x215n,
    jitshm_alias: 0x216n,
    unlink: 0xan,
    chmod: 0xfn,
    recvfrom: 0x1dn,
    getsockname: 0x20n,
    rename: 0x80n,
    sendto: 0x85n,
    mkdir: 0x88n,
    rmdir: 0x89n,
    stat: 0xbcn,
    getdents: 0x110n,
    lseek: 0x1den,
    dup2: 0x5an,
    fcntl: 0x5cn,
    select: 0x5dn,
    fstat: 0xbdn,
    umtx_op: 0x1c6n,
    cpuset_getaffinity: 0x1e7n,
    cpuset_setaffinity: 0x1e8n,
    rtprio_thread: 0x1d2n,
    ftruncate: 0x1e0n,
    sched_yield: 0x14bn,
    munmap: 0x49n,
    thr_new: 0x1c7n,
    thr_exit: 0x1afn,
    fsync: 0x5fn,
    ioctl: 0x36n,
    kill: 0x25n
};
