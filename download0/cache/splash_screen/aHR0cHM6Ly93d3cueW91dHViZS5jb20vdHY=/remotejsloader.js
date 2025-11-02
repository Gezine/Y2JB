/*
    Copyright (C) 2025 Gezine
    
    This software may be modified and distributed under the terms
    of the MIT license.  See the LICENSE file for details.
*/

(async function() {
    const AF_INET = 0x2n;
    const SOCK_STREAM = 0x1n;
    const SOL_SOCKET = 0xffffn;
    const SO_REUSEADDR = 0x4n;
    const MAXSIZE = 500 * 1024;

    const sockaddr_in = malloc(16);
    const addrlen = malloc(8);
    const enable = malloc(4);
    const len_ptr = malloc(8);
    const payload_buf = malloc(MAXSIZE);

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
    
    function create_socket() {
        // Clear sockaddr
        for(let i = 0; i < 16; i++) write8(sockaddr_in + BigInt(i), 0);
        
        const sock_fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
        
        if (Number(sock_fd) < 0) {
            throw new Error("Socket creation failed: " + toHex(sock_fd));
        }
        
        write32(enable, 1);
        syscall(SYSCALL.setsockopt, sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

        write8(sockaddr_in + 1n, AF_INET);
        write16(sockaddr_in + 2n, 0);        // port 0
        write32(sockaddr_in + 4n, 0);        // INADDR_ANY
        
        const bind_ret = syscall(SYSCALL.bind, sock_fd, sockaddr_in, 16n);
        if (bind_ret !== 0n) {
            throw new Error("Bind failed: " + toHex(bind_ret));
        }
                        
        const listen_ret = syscall(SYSCALL.listen, sock_fd, 3n);
        if (listen_ret !== 0n) {
            throw new Error("Listen failed: " + toHex(listen_ret));
        }
        
        return sock_fd;
    }

    let sock_fd = null;
    let port = 0;
    let attempts = 0;
    const MAX_ATTEMPTS = 60000;
    
    // Keep trying until we get port 50000 or reach max attempts
    while (port !== 50000 && attempts < MAX_ATTEMPTS) {
        sock_fd = create_socket();
        
        // Get assigned port
        write32(len_ptr, 16);
        syscall(SYSCALL.getsockname, sock_fd, sockaddr_in, len_ptr);
        
        const port_be = read16(sockaddr_in + 2n);
        port = Number(((port_be & 0xFFn) << 8n) | ((port_be >> 8n) & 0xFFn));
        
        attempts++;
        
        if (port !== 50000 && attempts < MAX_ATTEMPTS) {
            syscall(SYSCALL.close, sock_fd);
        }
    }
    
    const current_ip = get_current_ip();
    const network_str = current_ip ? (current_ip + ":" + port) : ("port " + port);
    
    if (current_ip === null) {
        send_notification("No network available!\nAborting...");
        throw new Error("No network available!\nAborting...");
    } else {
        await log("Remote JS Loader listening on " + network_str);
        send_notification("Remote JS Loader\nListening on " + network_str);
    }
    
    const decoder = new TextDecoder('utf-8');
    
    while (true) {
        try {
            await log("Awaiting connection at " + network_str);
            
            write32(addrlen, 16);
            const client_fd = syscall(SYSCALL.accept, sock_fd, sockaddr_in, addrlen);
            
            if (Number(client_fd) < 0) {
                await log("accept() failed: " + toHex(client_fd) + " - recreating socket");
                syscall(SYSCALL.close, sock_fd);
                sock_fd = create_socket();
                await log("Socket recreated");
                continue;
            }
            
            await log("Client connected, fd: " + Number(client_fd));
            
            let total_read = 0;
            let read_error = false;
            
            while (total_read < MAXSIZE) {
                const bytes_read = syscall(SYSCALL.read, client_fd, 
                    payload_buf + BigInt(total_read), 
                    BigInt(MAXSIZE - total_read));
                
                const n = Number(bytes_read);
                
                if (n === 0) {
                    break;
                }
                if (n < 0) {
                    await log("read() error: " + n);
                    read_error = true;
                    break;
                }
                
                await log("Read " + n + " bytes");
                total_read += n;
            }
            
            await log("Finished reading, total=" + total_read + " error=" + read_error);
            
            if (read_error || total_read === 0) {
                await log("No valid data received");
                syscall(SYSCALL.close, client_fd);
                continue;
            }
            
            const bytes = new Uint8Array(total_read);
            for (let i = 0; i < total_read; i++) {
                bytes[i] = Number(read8(payload_buf + BigInt(i)));
            }
            const js_code = decoder.decode(bytes);
            
            await log("Executing payload...");
            
            await eval(js_code);
            
            await log("Executed successfully");
            
            syscall(SYSCALL.close, client_fd);
            await log("Connection closed");
            
        } catch (e) {
            await log("ERROR in accept loop: " + e.message);
            await log(e.stack);
        }
    }
})();