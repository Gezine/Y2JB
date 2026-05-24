(async function() {
    check_jailbroken();
    
    await log("Test 1 : Direct syscall");
    let sym_addr = alloc_string("sceKernelAllocateMainDirectMemory");
    let addr_out = malloc(0x10);
    
    let result = syscall(SYSCALL.dlsym, LIBKERNEL_HANDLE, sym_addr, addr_out);
    if (result === 0xffffffffffffffffn) {
        await log("dlsym error: " + get_error_string());
    }

    await log("sceKernelAllocateMainDirectMemory : " +  toHex(read64(addr_out)));
    
    await log("Test 2 : sceKernelDlsym");
    
    let sceKernelAllocateMainDirectMemory = dlsym(LIBKERNEL_HANDLE, "sceKernelAllocateMainDirectMemory");
    await log("sceKernelAllocateMainDirectMemory : " +  toHex(sceKernelAllocateMainDirectMemory));
    
})();
