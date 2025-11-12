# Y2JB

Userland code execution using the PS5 YouTube app.

## Requirements

- At least 4.03 firmware PS5

### For Jailbroken PS5 (Webkit, Lua, BD-JB)
- Fake or legit activated PS5
- USA YouTube app version 1.03 PKG
- FTP access to the console

### For Non-Jailbroken PS5
- USB flash drive
- Pre-made backup file

## Setup Instructions

### Configure Network DNS Settings

1. Navigate to **Settings > Network > Settings > Set Up Internet Connection**
2. Scroll to the bottom and select **Set Up Manually**
3. Choose your connection type:
   - **Use WiFi**: Enter network name and password manually, set security to "WPA-Personal..."
   - **Use a LAN Cable**: Proceed to next step
4. Under **DNS Settings**, change from "Automatic" to **Manual**
5. Set **Primary DNS** to `127.0.0.2` (leave Secondary DNS blank)
6. Press **Done** and wait for the connection to establish

**Note:** You may see a network/PSN connection error - this is expected and can be ignored. The console will still function normally for YouTube payload delivery.

**Alternative:** Block PSN servers and `www.youtube.com` from your custom DNS server instead of using 127.0.0.2

### Fake Account Activation

**Note:** If you're using the backup file from the releases page, you can skip this section.

You need a **fake-activated account** to run Y2JB properly.

**If you have a legit PSN-activated account:** This means your account is officially registered and activated through PlayStation Network. You cannot use this account directly with Y2JB - you must create and use a separate fake-activated account instead.

**To fake activate an account:**
1. Open **etaHEN toolbox** while logging in to created new offline account
2. Navigate to the **"Remote Play"** menu
3. The account will be automatically fake activated

### Jailbroken PS5

1. Install YouTube app version 1.03 PKG on your PS5
2. Use FTP to access the following path (create if not present):
   ```
   /user/download/PPSA01650
   ```
3. Download `download0.dat` from the releases page and send it using FTP

### Non-Jailbroken PS5

1. Download the backup file from the releases page
2. Follow Sony's official guide to [restore backup data from USB](https://www.playstation.com/en-gb/support/hardware/back-up-ps5-data-USB/)  
**Note: Restoring backup WILL FACTORY RESET YOUR PS5**

## Sending Payloads

**Note:** The Remote JS Server does not always run on port 50000. Most of the time it will use port 50000, but rarely it may use a different port - this is not a bug.

Payloads can be sent using `payload_sender.py` with Python installed.

**Usage:**
```
python payload_sender.py <host> <file>
python payload_sender.py <host> <port> <file>
```

**Examples:**
```
python payload_sender.py 192.168.1.100 helloworld.js
python payload_sender.py 192.168.1.100 50000 helloworld.js
python payload_sender.py 192.168.1.100 9020 payload.bin
```

### Lapse Payload

**Firmware Compatibility:** Only works up to firmware 10.01

After the Lapse payload succeeds, you need to send the HEN or other elf binary to port **9021**. You can use any TCP payload sender such as:
- `netcat`
- `payload_sender.py`

**Example:**
```
python payload_sender.py 192.168.1.100 9021 hen.bin
```

## Credits

* **[shahrilnet](https://github.com/shahrilnet), [null_ptr](https://github.com/n0llptr)** - Referenced many codes from [Remote Lua Loader](https://github.com/shahrilnet/remote_lua_loader)
* **[ntfargo](https://github.com/ntfargo)** - Thanks for providing V8 CVEs and CTF writeups
* **abc and psfree team** - Lapse implementation
* **[flat_z](https://github.com/flatz) and [LM](https://github.com/LightningMods)** - Helping implement GPU rw using direct ioctl
* **[john-tornblom](https://github.com/john-tornblom) and [EchoStretch](https://github.com/EchoStretch)** - Providing elfldr.elf payload
* **[hammer-83](https://github.com/hammer-83)** - Various BD-J PS5 exploit references
* **[zecoxao](https://github.com/zecoxao), [idlesauce](https://github.com/idlesauce), and [TheFlow](https://github.com/theofficialflow)** - Helping troubleshoot dlsym
* **[Dr.Yenyen](https://github.com/DrYenyen) and PS5 R&D community** - Testing Y2JB
* **Rush** - Creating Y2JB backup file

## Disclaimer

This tool is provided as-is for research and development purposes only. Use at your own risk. The developers are not responsible for any damage, data loss, or consequences resulting from the use of this software.