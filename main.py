import pymem
import pymem.process
import struct
from typing import Tuple, Optional

# Memory patterns for finding GNames and GObjects
PATTERNS = {
    # Legacy patterns (fallback)
    'GNames_Legacy1': b"\x75\x05\xE8\x00\x00\x00\x00\x85\xDB\x75\x31",
    'GObjects_Legacy1': b"\xE8\x00\x00\x00\x00\x8B\x5D\xBF\x48",
    'GNames_Legacy2': b"\x48\x8B\x05\x6E\xDC\xFC\x01",
    'GObjects_Legacy2': b"\x48\x8B\x05\x33\xF2\x03\x02",
    'GObjects_Legacy3': b"\x48\x89\x05\x00\x00\x00\x00\x4C\x8D\x05\x00\x00\x00\x00\xBA\xFA\x02",
    
    # Current patterns as of 18/06/2025
    'GObjects_Current': b"\x48\x8B\xC8\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x0C\xC8",
    'GNames_Current1': b"\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\x0C\xC1",
    'GNames_Current2': b"\x49\x63\x06\x48\x8D\x55\xE8\x48\x8B\x0D\x00\x00\x00\x00\x48\x8B\x0C\xC1"
}

# Expected offset between GNames and GObjects
EXPECTED_OFFSET = 0x48

def scan_memory_pattern(pm: pymem.Pymem, module_base: int, module_size: int, 
                       pattern: bytes, pattern_name: str = "Unknown") -> Optional[int]:
    """
    Scan memory for a given byte pattern.
    
    Args:
        pm: Pymem instance for memory access
        module_base: Base address of the module
        module_size: Size of the module to scan
        pattern: Byte pattern to search for (use 0x00 for wildcards)
        pattern_name: Name of the pattern for logging
    
    Returns:
        Address where pattern was found, or None if not found
    """
    try:
        print(f"[*] Scanning for {pattern_name} at {hex(module_base)}...")
        memory_dump = pm.read_bytes(module_base, module_size)
        
        for i in range(len(memory_dump) - len(pattern)):
            if _pattern_matches(memory_dump, i, pattern):
                found_address = module_base + i
                print(f"[+] Found {pattern_name} at {hex(found_address)}")
                return found_address
                
        print(f"[-] Pattern {pattern_name} not found")
        return None
        
    except Exception as e:
        print(f"[!] Scan failed for {pattern_name}: {e}")
        return None

def _pattern_matches(memory_dump: bytes, start_index: int, pattern: bytes) -> bool:
    """Check if a pattern matches at the given memory location."""
    for j in range(len(pattern)):
        if pattern[j] != 0x00 and memory_dump[start_index + j] != pattern[j]:
            return False
    return True

def extract_gobjects_address(pm: pymem.Pymem, pattern_address: int) -> Optional[int]:
    """
    Extract GObjects address from the current pattern.
    Pattern: 48 8B C8 48 8B 05 ?? ?? ?? ?? 48 8B 0C C8
    """
    try:
        # Relative offset is at pattern_address + 6 (after 48 8B 05)
        offset_address = pattern_address + 6
        relative_offset = struct.unpack("i", pm.read_bytes(offset_address, 4))[0]
        final_address = offset_address + relative_offset + 4
        return final_address
    except Exception as e:
        print(f"[!] Failed to extract GObjects address: {e}")
        return None

def extract_gnames_address_method1(pm: pymem.Pymem, pattern_address: int) -> Optional[int]:
    """
    Extract GNames address from the first current pattern.
    Pattern: 48 8B 0D ?? ?? ?? ?? 48 8B 0C C1
    """
    try:
        # Relative offset is at pattern_address + 3 (after 48 8B 0D)
        offset_address = pattern_address + 3
        relative_offset = struct.unpack("i", pm.read_bytes(offset_address, 4))[0]
        final_address = offset_address + relative_offset + 4
        return final_address
    except Exception as e:
        print(f"[!] Failed to extract GNames address (method 1): {e}")
        return None

def extract_gnames_address_method2(pm: pymem.Pymem, pattern_address: int) -> Optional[int]:
    """
    Extract GNames address from the second current pattern.
    Pattern: 49 63 06 48 8D 55 E8 48 8B 0D ?? ?? ?? ?? 48 8B 0C C1
    """
    try:
        # Relative offset is at pattern_address + 10 (after the longer prefix)
        offset_address = pattern_address + 10
        relative_offset = struct.unpack("i", pm.read_bytes(offset_address, 4))[0]
        final_address = offset_address + relative_offset + 4
        return final_address
    except Exception as e:
        print(f"[!] Failed to extract GNames address (method 2): {e}")
        return None

def extract_gnames_address_legacy(pm: pymem.Pymem, pattern_address: int) -> Optional[int]:
    """Extract GNames address using legacy pattern method."""
    try:
        offset = pattern_address + 3
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        addr = offset + rel_offset + 4
        addr += 0x27  # Additional offset from legacy code
        offset = addr + 3
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        final_addr = offset + rel_offset + 4
        return final_addr
    except Exception as e:
        print(f"[!] Legacy GNames extraction failed: {e}")
        return None

def extract_gobjects_address_legacy(pm: pymem.Pymem, pattern_address: int) -> Optional[int]:
    """Extract GObjects address using legacy pattern method."""
    try:
        offset = pattern_address + 1
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        addr = offset + rel_offset + 4
        addr += 0x65  # Additional offset from legacy code
        offset = addr + 3
        rel_offset = struct.unpack("i", pm.read_bytes(offset, 4))[0]
        final_addr = offset + rel_offset + 4
        return final_addr
    except Exception as e:
        print(f"[!] Legacy GObjects extraction failed: {e}")
        return None

def find_gnames_gobjects_offsets() -> Tuple[Optional[int], Optional[int]]:
    """
    Find GNames and GObjects offsets in Rocket League process.
    
    Returns:
        Tuple of (gnames_offset, gobjects_offset) relative to module base
    """
    try:
        print("[*] Attaching to Rocket League process...")
        pm = pymem.Pymem("RocketLeague.exe")
        
        module = pymem.process.module_from_name(pm.process_handle, "RocketLeague.exe")
        base_address = module.lpBaseOfDll
        module_size = module.SizeOfImage
        
        print(f"[*] Module base address: {hex(base_address)}")
        print(f"[*] Module size: {hex(module_size)}")
        
        gnames_address = None
        gobjects_address = None
        
        # Try current patterns first
        print("\n[*] Attempting current patterns...")
        
        # Find GObjects using current pattern
        gobjects_pattern_addr = scan_memory_pattern(
            pm, base_address, module_size, 
            PATTERNS['GObjects_Current'], "GObjects (Current)"
        )
        if gobjects_pattern_addr:
            gobjects_address = extract_gobjects_address(pm, gobjects_pattern_addr)
            print(f"[+] GObjects address: {hex(gobjects_address) if gobjects_address else 'Failed'}")
        
        # Find GNames using current patterns
        gnames_pattern_addr = scan_memory_pattern(
            pm, base_address, module_size, 
            PATTERNS['GNames_Current1'], "GNames (Current Method 1)"
        )
        if gnames_pattern_addr:
            gnames_address = extract_gnames_address_method1(pm, gnames_pattern_addr)
            print(f"[+] GNames address (method 1): {hex(gnames_address) if gnames_address else 'Failed'}")
        
        # Try second GNames pattern if first failed
        if not gnames_address:
            gnames_pattern_addr = scan_memory_pattern(
                pm, base_address, module_size, 
                PATTERNS['GNames_Current2'], "GNames (Current Method 2)"
            )
            if gnames_pattern_addr:
                gnames_address = extract_gnames_address_method2(pm, gnames_pattern_addr)
                print(f"[+] GNames address (method 2): {hex(gnames_address) if gnames_address else 'Failed'}")
        
        # Fallback to legacy patterns if current patterns failed
        if not gnames_address or not gobjects_address:
            print("\n[*] Current patterns failed, attempting legacy patterns...")
            
            if not gnames_address:
                gnames_pattern_addr = scan_memory_pattern(
                    pm, base_address, module_size, 
                    PATTERNS['GNames_Legacy1'], "GNames (Legacy 1)"
                )
                if gnames_pattern_addr:
                    gnames_address = extract_gnames_address_legacy(pm, gnames_pattern_addr)
                    print(f"[+] GNames address (legacy): {hex(gnames_address) if gnames_address else 'Failed'}")
            
            if not gobjects_address:
                gobjects_pattern_addr = scan_memory_pattern(
                    pm, base_address, module_size, 
                    PATTERNS['GObjects_Legacy1'], "GObjects (Legacy 1)"
                )
                if gobjects_pattern_addr:
                    gobjects_address = extract_gobjects_address_legacy(pm, gobjects_pattern_addr)
                    print(f"[+] GObjects address (legacy): {hex(gobjects_address) if gobjects_address else 'Failed'}")
        
        # Try additional legacy patterns if still not found
        if not gnames_address or not gobjects_address:
            print("\n[*] Attempting additional legacy patterns...")
            for pattern_name, pattern in PATTERNS.items():
                if pattern_name.startswith('GNames_Legacy2') and not gnames_address:
                    addr = scan_memory_pattern(pm, base_address, module_size, pattern, pattern_name)
                    if addr:
                        rel_offset = struct.unpack("i", pm.read_bytes(addr + 3, 4))[0]
                        gnames_address = addr + rel_offset + 7
                
                if pattern_name.startswith('GObjects_Legacy2') and not gobjects_address:
                    addr = scan_memory_pattern(pm, base_address, module_size, pattern, pattern_name)
                    if addr:
                        rel_offset = struct.unpack("i", pm.read_bytes(addr + 3, 4))[0]
                        gobjects_address = addr + rel_offset + 7

        # Validate and adjust addresses if needed
        if gnames_address and gobjects_address:
            actual_offset = abs(gobjects_address - gnames_address)
            if actual_offset != EXPECTED_OFFSET:
                print(f"[?] Unexpected offset difference: {hex(actual_offset)} (expected: {hex(EXPECTED_OFFSET)})")
                gnames_address = gobjects_address - EXPECTED_OFFSET
                print(f"[*] Adjusted GNames address: {hex(gnames_address)}")
            
            # Convert to relative offsets
            gnames_offset = gnames_address - base_address
            gobjects_offset = gobjects_address - base_address
            
            return gnames_offset, gobjects_offset
        
        return None, None

    except Exception as e:
        print(f"[!] Error during offset discovery: {e}")
        return None, None

def main():
    """Main function to find and display Rocket League offsets."""
    print("=" * 60)
    print("Rocket League Offset Finder")
    print("=" * 60)
    
    gnames_offset, gobjects_offset = find_gnames_gobjects_offsets()
    
    if gnames_offset is not None and gobjects_offset is not None:
        print("\n" + "=" * 60)
        print("OFFSETS FOUND")
        print("=" * 60)
        print(f"GNames:   {hex(gnames_offset)} ({gnames_offset})")
        print(f"GObjects: {hex(gobjects_offset)} ({gobjects_offset})")
    else:
        print("\n" + "=" * 60)
        print("FAILED TO FIND OFFSETS")
        print("=" * 60)
        print("The script was unable to locate the required memory patterns.")
        print("This could be due to:")
        print("- Rocket League not running")
        print("- Game version mismatch")
        print("- Anti-cheat interference")
        print("- Memory layout changes")

if __name__ == "__main__":
    main()
