(async function() {
    const sym_addr = alloc_string("sceKernelAllocateMainDirectMemory");
    const addr_out = malloc(0x10);
    
    const result = syscall(0x24fn, 0x2001n, sym_addr, addr_out);
    if (result === 0xffffffffffffffffn) {
        await log("dlsym error: " + get_error_string());
    }

    await log("sceKernelAllocateMainDirectMemory : " +  toHex(read64(addr_out)));
    
})();