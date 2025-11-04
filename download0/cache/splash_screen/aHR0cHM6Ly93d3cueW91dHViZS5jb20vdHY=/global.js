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

// Global objects
let allocated_buffers = [];
let eboot_base = 0n;
let libc_base = 0n;
let return_value_addr;
let libkernel_base;
let syscall_wrapper;
let firmwareVersion;
let rop_chain;
let fake_bc;
let fake_frame;
let return_value_buf;
let saved_fp = 0n;

const PAGE_SIZE = 0x4000n;
const PHYS_PAGE_SIZE = 0x1000n;

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
const O_CREAT = 0x100n;
const O_TRUNC = 0x1000n;
const O_APPEND = 0x2000n;
const O_NONBLOCK = 0x4000n;

const SIGILL = 4n;
const SIGBUS = 10n;
const SIGSEGV = 11n;
const SA_SIGINFO = 0x4n;

const LIBKERNEL_HANDLE = 0x2001n;

let SYSCALL = {
    read: 0x3n,
    write: 0x4n,
    open: 0x5n,
    close: 0x6n,
    getuid: 0x18n,
    getsockname: 0x20n,
    accept: 0x1en,
    socket: 0x61n,
    connect: 0x62n,
    bind: 0x68n,
    setsockopt: 0x69n,
    listen: 0x6an,
    getsockopt: 0x76n,
    sysctl: 0xcan,
    netgetiflist: 0x7dn,
};

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