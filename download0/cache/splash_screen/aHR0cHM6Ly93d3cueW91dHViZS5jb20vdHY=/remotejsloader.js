(async function() {
    const MAXSIZE = 500 * 1024;

    const sockaddr_in = malloc(16);
    const addrlen = malloc(8);
    const enable = malloc(4);
    const len_ptr = malloc(8);
    const payload_buf = malloc(MAXSIZE);

    function create_socket() {
        // Clear sockaddr
        for (let i = 0; i < 16; i++) write8(sockaddr_in + BigInt(i), 0);

        const sock_fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
        if (sock_fd === 0xffffffffffffffffn) {
            throw new Error("Socket creation failed: " + toHex(sock_fd));
        }

        write32(enable, 1);
        syscall(SYSCALL.setsockopt, sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

        write8(sockaddr_in + 1n, AF_INET);
        write16(sockaddr_in + 2n, 0);        // port 0
        write32(sockaddr_in + 4n, 0);        // INADDR_ANY

        const bind_ret = syscall(SYSCALL.bind, sock_fd, sockaddr_in, 16n);
        if (bind_ret === 0xffffffffffffffffn) {
            syscall(SYSCALL.close, sock_fd);
            throw new Error("Bind failed: " + toHex(bind_ret));
        }

        const listen_ret = syscall(SYSCALL.listen, sock_fd, 3n);
        if (listen_ret === 0xffffffffffffffffn) {
            syscall(SYSCALL.close, sock_fd);
            throw new Error("Listen failed: " + toHex(listen_ret));
        }

        return sock_fd;
    }

    function get_port(sock_fd) {
        write32(len_ptr, 16);
        syscall(SYSCALL.getsockname, sock_fd, sockaddr_in, len_ptr);

        const port_be = read16(sockaddr_in + 2n);
        return Number(((port_be & 0xFFn) << 8n) | ((port_be >> 8n) & 0xFFn));
    }

    async function setup_socket_until_port_50000() {
        let sock_fd = null;
        let port = 0;
        let attempts = 0;
        const MAX_ATTEMPTS = 60000;

        let last_sock = null;
        let last_port = 0;

        while (port !== 50000 && attempts < MAX_ATTEMPTS) {
            try {
                sock_fd = create_socket();
            } catch (err) {
                attempts++;
                continue;
            }

            port = get_port(sock_fd);

            last_sock = sock_fd;
            last_port = port;

            if (port !== 50000) {
                syscall(SYSCALL.close, sock_fd);
            }

            attempts++;
        }
        
        if (port !== 50000) {
            if (last_sock !== null) {
                await log("Warning: did not get port 50000 after " + attempts + " attempts; using last assigned port " + last_port);
                return { sock_fd: last_sock, port: last_port };
            } else {
                throw new Error("Failed to create any socket after " + attempts + " attempts");
            }
        }

        return { sock_fd, port };
    }

    async function recreate_socket() {
        const sock_fd = create_socket();
        const port = get_port(sock_fd);

        const current_ip = get_current_ip();
        if (current_ip === null) {
            send_notification("No network available!\nAborting...");
            throw new Error("No network available!\nAborting...");
        }

        const network_str = current_ip + ":" + port;
        await log("Socket recreated on " + network_str);
        send_notification("Remote JS Loader\nListening on " + network_str);

        return { sock_fd, port, network_str };
    }

    // Initial setup (retry until port 50000, but fall back to last random port if attempts exhausted)
    let { sock_fd, port } = await setup_socket_until_port_50000();

    const current_ip = get_current_ip();
    if (current_ip === null) {
        send_notification("No network available!\nAborting...");
        throw new Error("No network available!\nAborting...");
    }

    let network_str = current_ip + ":" + port;
    await log("Remote JS Loader listening on " + network_str);
    send_notification("Remote JS Loader\nListening on " + network_str);

    const decoder = new TextDecoder('utf-8');

    while (true) {
        try {
            await log("Awaiting connection at " + network_str);

            write32(addrlen, 16);
            const client_fd = syscall(SYSCALL.accept, sock_fd, sockaddr_in, addrlen);

            if (client_fd === 0xffffffffffffffffn) {
                await log("accept() failed: " + toHex(client_fd) + " - recreating socket");
                syscall(SYSCALL.close, sock_fd);

                const recreated = await recreate_socket();
                sock_fd = recreated.sock_fd;
                port = recreated.port;
                network_str = recreated.network_str;
                continue;
            }

            await log("Client connected, fd: " + Number(client_fd));

            let total_read = 0;
            let read_error = false;

            while (total_read < MAXSIZE) {
                const bytes_read = syscall(
                    SYSCALL.read,
                    client_fd,
                    payload_buf + BigInt(total_read),
                    BigInt(MAXSIZE - total_read)
                );

                const n = Number(bytes_read);

                if (n === 0) break;
                if (n < 0) {
                    await log("read() error: " + n);
                    read_error = true;
                    break;
                }

                total_read += n;
                await log("Read " + n + " bytes");
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
