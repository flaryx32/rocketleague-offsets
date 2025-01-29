import pymem
import pymem.process
import struct

# patterns n stuff (redundancy yay)
PATTERNS = {
    # some patterns from forums n stuff
    'GNames_1': b"\x75\x05\xE8\x00\x00\x00\x00\x85\xDB\x75\x31",
    'GObjects_1': b"\xE8\x00\x00\x00\x00\x8B\x5D\xBF\x48",
    
    # alt patterns (different approach)
    'GNames_2': b"\x48\x8B\x05\x6E\xDC\xFC\x01",
    'GObjects_2': b"\x48\x8B\x05\x33\xF2\x03\x02",
    
    # another backup pattern just in case
    'GObjects_3': b"\x48\x89\x05\x00\x00\x00\x00\x4C\x8D\x05\x00\x00\x00\x00\xBA\xFA\x02"
}

def pattern_scan(pm, module_base, module_size, pattern, pattern_name="Unknown"):
    """ scan memory for given pattern, print debug stuff """
    try:
        print(f"[*] scanning for {pattern_name} at {hex(module_base)}...")
        bytes_dump = pm.read_bytes(module_base, module_size)
        
        for i in range(len(bytes_dump) - len(pattern)):
            match = True
            for j in range(len(pattern)):
                if pattern[j] != 0x00 and bytes_dump[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                found_addr = module_base + i
                print(f"[+] found {pattern_name} at {hex(found_addr)}!")
                return found_addr
                
        return None
        
    except Exception as e:
        print(f"[!] scan failed for {pattern_name}: {e}")
        return None

def get_gnames_method1(pm, base_addr, pattern_addr):
    """ attempt to find gnames using first method """
    try:
        offset = pattern_addr + 3
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        addr = offset + rel_offset + 4
        addr += 0x27  # some extra offset from forum code
        offset = addr + 3
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        final_addr = offset + rel_offset + 4
        return final_addr
    except Exception as e:
        print(f"[!] method 1 gnames failed: {e}")
        return None

def get_gobjects_method1(pm, base_addr, pattern_addr):
    """ attempt to find gobjects using first method """
    try:
        offset = pattern_addr + 1
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        addr = offset + rel_offset + 4
        addr += 0x65  # another offset from forum code
        offset = addr + 3
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        final_addr = offset + rel_offset + 4
        return final_addr
    except Exception as e:
        print(f"[!] method 1 gobjects failed: {e}")
        return None

def find_gnames_gobjects():
    try:
        print("[*] attaching to Rocket League...")
        pm = pymem.Pymem("RocketLeague.exe")
        
        module = pymem.process.module_from_name(pm.process_handle, "RocketLeague.exe")
        base_address = module.lpBaseOfDll
        module_size = module.SizeOfImage
        
        print(f"[*] base addr: {hex(base_address)}")
        
        gnames_addr = None
        gobjects_addr = None
        
        print("\n[*] trying method 1...")
        gnames_pattern_addr = pattern_scan(pm, base_address, module_size, PATTERNS['GNames_1'], "GNames 1")
        if gnames_pattern_addr:
            gnames_addr = get_gnames_method1(pm, base_address, gnames_pattern_addr)
            print(f"[+] gnames 1: {hex(gnames_addr) if gnames_addr else 'failed'}")
        
        gobjects_pattern_addr = pattern_scan(pm, base_address, module_size, PATTERNS['GObjects_1'], "GObjects 1")
        if gobjects_pattern_addr:
            gobjects_addr = get_gobjects_method1(pm, base_address, gobjects_pattern_addr)
            print(f"[+] gobjects 1: {hex(gobjects_addr) if gobjects_addr else 'failed'}")
        
        if not gnames_addr or not gobjects_addr:
            print("\n[*] method 1 failed, trying method 2...")
            for pattern_name, pattern in PATTERNS.items():
                if pattern_name.startswith('GNames_2') and not gnames_addr:
                    addr = pattern_scan(pm, base_address, module_size, pattern, pattern_name)
                    if addr:
                        rel_offset = struct.unpack("i", pm.read_bytes(addr + 3, 4))[0]
                        gnames_addr = addr + rel_offset + 7
                
                if pattern_name.startswith('GObjects_2') and not gobjects_addr:
                    addr = pattern_scan(pm, base_address, module_size, pattern, pattern_name)
                    if addr:
                        rel_offset = struct.unpack("i", pm.read_bytes(addr + 3, 4))[0]
                        gobjects_addr = addr + rel_offset + 7

        if gnames_addr and gobjects_addr:
            diff = abs(gobjects_addr - gnames_addr)
            if diff != 0x48:
                print(f"[?] unexpected offset diff: {hex(diff)} (should be 0x48)")
                gnames_addr = gobjects_addr - 0x48
                print(f"[*] adjusted gnames: {hex(gnames_addr)}")
            
            return (gnames_addr - base_address, gobjects_addr - base_address)
        
        return None, None

    except Exception as e:
        print(f"[!] error: {str(e)}")
        return None, None

if __name__ == "__main__":
    print("[*] starting RL offset finder...")
    offsets = find_gnames_gobjects()
    
    if offsets[0] is not None and offsets[1] is not None:
        print(f"\nfound offsets:")
        print(f"gnames:   {hex(offsets[0])} ({offsets[0]})")
        print(f"gobjects: {hex(offsets[1])} ({offsets[1]})")
        
        print("\nSDK format:")
        print(f'"GNames": {offsets[0]},')
        print(f'"GObjects": {offsets[1]},')
    else:
        print("\nfailed to find offsets.")
