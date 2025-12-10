import ctypes
from ctypes import wintypes
import sys
import struct
import json
import time
import urllib.request
import urllib.error
import os

# --- Win32 API Constants and Structures ---

PROCESS_ALL_ACCESS = 0x1F0FFF

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]

psapi = ctypes.WinDLL('psapi')
kernel32 = ctypes.WinDLL('kernel32')

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

EnumProcessModules = psapi.EnumProcessModules
EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
EnumProcessModules.restype = wintypes.BOOL

GetModuleBaseNameA = psapi.GetModuleBaseNameA
GetModuleBaseNameA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.c_char_p, wintypes.DWORD]
GetModuleBaseNameA.restype = wintypes.DWORD

GetModuleInformation = psapi.GetModuleInformation
GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(MODULEINFO), wintypes.DWORD]
GetModuleInformation.restype = wintypes.BOOL

GetModuleFileNameExA = psapi.GetModuleFileNameExA
GetModuleFileNameExA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.c_char_p, wintypes.DWORD]
GetModuleFileNameExA.restype = wintypes.DWORD

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

# --- Offsets (Unity 2021/2022 x64) ---
OFFSETS = {
    'AssemblyImage': 0x60,
    'ReferencedAssemblies': 0xa0,
    'ImageClassCache': 0x4d0, # Will be scanned
    'HashTableSize': 0x18,
    'HashTableTable': 0x20,
    'TypeDefinitionNextClassCache': 0x108, 
    'TypeDefinitionName': 0x48,
    'TypeDefinitionFields': 0x98,
    'TypeDefinitionFieldCount': 0x100, 
    'TypeDefinitionFieldSize': 0x20,
    'TypeDefinitionRuntimeInfo': 0xD0,
    'TypeDefinitionRuntimeInfoDomainVTables': 0x8,
    'TypeDefinitionVTableSize': 0x5C,
    'VTable': 0x48,
    'TypeDefinitionParent': 0x30,
}

PTR_SIZE = 8

class ProcessMemory:
    def __init__(self, pid):
        self.pid = pid
        self.handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not self.handle:
            raise Exception(f"Could not open process {pid}. Error: {ctypes.GetLastError()}")

    def close(self):
        CloseHandle(self.handle)

    def read_bytes(self, address, size):
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()
        if not ReadProcessMemory(self.handle, address, buffer, size, ctypes.byref(bytes_read)):
            return None
        return buffer.raw

    def read_ptr(self, address):
        data = self.read_bytes(address, PTR_SIZE)
        if data:
            return struct.unpack('<Q', data)[0]
        return 0

    def read_int32(self, address):
        data = self.read_bytes(address, 4)
        if data:
            return struct.unpack('<i', data)[0]
        return 0
    
    def read_uint32(self, address):
        data = self.read_bytes(address, 4)
        if data:
            return struct.unpack('<I', data)[0]
        return 0

    def read_cstring(self, address):
        result = b""
        offset = 0
        while True:
            chunk = self.read_bytes(address + offset, 16)
            if not chunk: break
            if b'\x00' in chunk:
                result += chunk.split(b'\x00')[0]
                break
            result += chunk
            offset += 16
            if len(result) > 256: break
        return result.decode('utf-8', errors='ignore')

def get_mtga_pid():
    Snapshot = kernel32.CreateToolhelp32Snapshot
    Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    Snapshot.restype = wintypes.HANDLE
    
    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260)]

    Process32First = kernel32.Process32First
    Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    Process32First.restype = wintypes.BOOL
    
    Process32Next = kernel32.Process32Next
    Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    Process32Next.restype = wintypes.BOOL
    
    hSnap = Snapshot(0x00000002, 0) 
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    
    if Process32First(hSnap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile == b'MTGA.exe':
                CloseHandle(hSnap)
                return pe.th32ProcessID
            if not Process32Next(hSnap, ctypes.byref(pe)):
                break
    CloseHandle(hSnap)
    return None

def get_mono_module(pm):
    hMods = (wintypes.HMODULE * 1024)()
    cbNeeded = wintypes.DWORD()
    if EnumProcessModules(pm.handle, hMods, ctypes.sizeof(hMods), ctypes.byref(cbNeeded)):
        count = cbNeeded.value // ctypes.sizeof(wintypes.HMODULE)
        for i in range(count):
            modName = ctypes.create_string_buffer(260)
            if GetModuleBaseNameA(pm.handle, hMods[i], modName, ctypes.sizeof(modName)):
                if modName.value == b'mono-2.0-bdwgc.dll':
                    modInfo = MODULEINFO()
                    GetModuleInformation(pm.handle, hMods[i], ctypes.byref(modInfo), ctypes.sizeof(modInfo))
                    fullPath = ctypes.create_string_buffer(1024)
                    GetModuleFileNameExA(pm.handle, hMods[i], fullPath, ctypes.sizeof(fullPath))
                    return modInfo.lpBaseOfDll, fullPath.value.decode()
    return None, None

def get_root_domain_address(pm, base_address, dll_path):
    try:
        with open(dll_path, 'rb') as f:
            content = f.read()
    except Exception as e:
        print(f"Could not read mono dll at {dll_path}: {e}")
        return 0

    try:
        pe_sig_offset = struct.unpack_from('<I', content, 0x3c)[0]
        magic = struct.unpack_from('<H', content, pe_sig_offset + 24)[0]
        is_64 = magic == 0x20b
        rva_count_offset = pe_sig_offset + 24 + (112 if is_64 else 96)
        export_table_rva = struct.unpack_from('<I', content, rva_count_offset)[0]
        if export_table_rva == 0: return 0
        
        num_sections = struct.unpack_from('<H', content, pe_sig_offset + 6)[0]
        opt_header_size = struct.unpack_from('<H', content, pe_sig_offset + 20)[0]
        section_table_start = pe_sig_offset + 24 + opt_header_size
        
        def rva_to_offset(rva):
            for i in range(num_sections):
                sec_start = section_table_start + i * 40
                virt_addr = struct.unpack_from('<I', content, sec_start + 12)[0]
                raw_ptr = struct.unpack_from('<I', content, sec_start + 20)[0]
                virt_size = struct.unpack_from('<I', content, sec_start + 8)[0]
                if virt_addr <= rva < virt_addr + virt_size:
                    return raw_ptr + (rva - virt_addr)
            return rva 

        export_offset = rva_to_offset(export_table_rva)
        num_funcs = struct.unpack_from('<I', content, export_offset + 20)[0]
        num_names = struct.unpack_from('<I', content, export_offset + 24)[0]
        funcs_rva = struct.unpack_from('<I', content, export_offset + 28)[0]
        names_rva = struct.unpack_from('<I', content, export_offset + 32)[0]
        ordinals_rva = struct.unpack_from('<I', content, export_offset + 36)[0]
        
        names_offset = rva_to_offset(names_rva)
        ordinals_offset = rva_to_offset(ordinals_rva)
        funcs_offset = rva_to_offset(funcs_rva)
        
        for i in range(num_names):
            name_rva = struct.unpack_from('<I', content, names_offset + i * 4)[0]
            name_file_offset = rva_to_offset(name_rva)
            name_end = content.find(b'\x00', name_file_offset)
            name = content[name_file_offset:name_end].decode()
            
            if name == 'mono_get_root_domain':
                ordinal = struct.unpack_from('<H', content, ordinals_offset + i * 2)[0]
                func_rva = struct.unpack_from('<I', content, funcs_offset + ordinal * 4)[0]
                return base_address + func_rva
                
    except Exception as e:
        print(f"Error parsing PE: {e}")
        return 0
    return 0

def find_class(pm, image_addr, class_name):
    # Search range around known offsets
    for off in range(0x400, 0x600, 8):
        size = pm.read_uint32(image_addr + off + OFFSETS['HashTableSize'])
        table = pm.read_ptr(image_addr + off + OFFSETS['HashTableTable'])
        
        if 10 < size < 50000 and table > 0x10000 and (table & 7) == 0:
             first_node = pm.read_ptr(table)
             if first_node == 0 or pm.read_ptr(first_node) != 0:
                 # Scan table
                 for i in range(size):
                    node = pm.read_ptr(table + i * PTR_SIZE)
                    loop_safe = 0
                    while node:
                        if loop_safe > 10000:
                            break
                        loop_safe += 1
                        
                        name_ptr = pm.read_ptr(node + OFFSETS['TypeDefinitionName'])
                        name = pm.read_cstring(name_ptr)
                        
                        if name == class_name:
                            return node
                        
                        node = pm.read_ptr(node + OFFSETS['TypeDefinitionNextClassCache'])
    return 0

def find_field(pm, class_addr, field_name):
    current_class = class_addr
    while current_class:
        field_count = pm.read_int32(current_class + OFFSETS['TypeDefinitionFieldCount'])
        fields_ptr = pm.read_ptr(current_class + OFFSETS['TypeDefinitionFields'])
        
        for i in range(field_count):
            field_addr = fields_ptr + i * 0x20
            name_ptr = pm.read_ptr(field_addr + 8)
            name = pm.read_cstring(name_ptr)
            if name == field_name:
                offset = pm.read_int32(field_addr + 0x18)
                return offset
        
        current_class = pm.read_ptr(current_class + OFFSETS['TypeDefinitionParent'])
        if not current_class: break
    return None

def get_static_field_address(pm, class_addr, field_name):
    offset = find_field(pm, class_addr, field_name)
    if offset is None:
        print(f"Field {field_name} not found")
        return 0
    
    runtime_info = pm.read_ptr(class_addr + OFFSETS['TypeDefinitionRuntimeInfo'])
    if not runtime_info: return 0
    
    domain_vtables_ptr = runtime_info + OFFSETS['TypeDefinitionRuntimeInfoDomainVTables']
    vtable_struct = pm.read_ptr(domain_vtables_ptr)
    if not vtable_struct: return 0
    
    vtable_size = pm.read_int32(class_addr + OFFSETS['TypeDefinitionVTableSize'])
    
    static_data_ptr_addr = vtable_struct + OFFSETS['VTable'] + (vtable_size * PTR_SIZE)
    static_data_ptr = pm.read_ptr(static_data_ptr_addr)
    
    return static_data_ptr + offset

def main():
    print("Searching for MTGA.exe...")
    pid = get_mtga_pid()
    if not pid:
        print("MTGA.exe not found. Is the game running?")
        return

    print(f"Found MTGA.exe (PID: {pid})")
    try:
        pm = ProcessMemory(pid)
    except Exception as e:
        print(f"Error accessing process memory: {e}")
        return

    base_addr, dll_path = get_mono_module(pm)
    if not base_addr:
        print("Could not find mono-2.0-bdwgc.dll")
        pm.close()
        return
    
    root_func = get_root_domain_address(pm, base_addr, dll_path)
    code = pm.read_bytes(root_func, 7)
    if code[0:3] == b'\x48\x8b\x05':
        offset = struct.unpack('<i', code[3:7])[0]
        rip = root_func + 7
        domain_ptr_addr = rip + offset
        domain_addr = pm.read_ptr(domain_ptr_addr)
    else:
        print("Could not parse mono_get_root_domain code.")
        pm.close()
        return

    assemblies_ptr = pm.read_ptr(domain_addr + OFFSETS['ReferencedAssemblies'])
    
    curr = assemblies_ptr
    wc_class = 0
    core_image_addr = 0
    
    # Iterate all assemblies to find WrapperController
    while curr:
        data = pm.read_ptr(curr)
        if not data: break
        
        image_addr = pm.read_ptr(data + OFFSETS['AssemblyImage'])
        if image_addr:
            wc_class = find_class(pm, image_addr, "WrapperController")
            if wc_class:
                core_image_addr = image_addr
                break
        
        curr = pm.read_ptr(curr + PTR_SIZE)
        
    if not wc_class:
        print("Could not find WrapperController in any assembly.")
        pm.close()
        return

    # 1. Get Instance
    print("Getting WrapperController.Instance...")
    instance_addr = get_static_field_address(pm, wc_class, "<Instance>k__BackingField")
    instance_ptr = pm.read_ptr(instance_addr)
    
    if not instance_ptr:
        print("Instance is null. Game might not be ready.")
        pm.close()
        return

    # 2. Get InventoryManager
    print("Getting InventoryManager...")
    # Note: InventoryManager class might be in the same assembly as WrapperController or Core
    inv_mgr_class = find_class(pm, core_image_addr, "InventoryManager")
    if not inv_mgr_class:
        # Try searching all assemblies if not found in Core
        curr = assemblies_ptr
        while curr:
            data = pm.read_ptr(curr)
            if not data: break
            image_addr = pm.read_ptr(data + OFFSETS['AssemblyImage'])
            if image_addr:
                inv_mgr_class = find_class(pm, image_addr, "InventoryManager")
                if inv_mgr_class: break
            curr = pm.read_ptr(curr + PTR_SIZE)
            
    if not inv_mgr_class:
        print("Could not find InventoryManager class definition.")
        pm.close()
        return
        
    inv_offset = find_field(pm, wc_class, "<InventoryManager>k__BackingField")
    if inv_offset is None:
        print("Field <InventoryManager>k__BackingField not found in WrapperController.")
        pm.close()
        return
        
    inv_mgr_ptr = pm.read_ptr(instance_ptr + inv_offset)
    
    if not inv_mgr_ptr:
        print("InventoryManager instance is null.")
        pm.close()
        return

    # 3. Get InventoryServiceWrapper
    # Assuming InventoryServiceWrapper class is needed to find field offset
    # We already know it's hard to find by name, so we use heuristic on the instance memory
    
    wrapper_offset = find_field(pm, inv_mgr_class, "_inventoryServiceWrapper")
    if wrapper_offset is None:
        print("Field _inventoryServiceWrapper not found in InventoryManager.")
        pm.close()
        return
        
    service_wrapper_ptr = pm.read_ptr(inv_mgr_ptr + wrapper_offset)
    
    if not service_wrapper_ptr:
        print("ServiceWrapper instance is null.")
        pm.close()
        return

    # 4. Get Cards Dictionary (Heuristic scan)
    print("Scanning ServiceWrapper for Cards dictionary...")
    cards_ptr = 0
    data = pm.read_bytes(service_wrapper_ptr, 128)
    if data:
        # Scan for a pointer that looks like a Dictionary
        # A dictionary has a 'entries' array which has a length.
        # We check offsets 0x10 to 0x80
        for off in range(0x10, 0x80, 8):
            ptr_val = struct.unpack('<Q', data[off:off+8])[0]
            if ptr_val > 0x10000 and (ptr_val & 7) == 0:
                # Check entries pointer at +0x18 (standard Mono Dictionary layout)
                entries = pm.read_ptr(ptr_val + 0x18)
                if entries > 0x10000 and (entries & 7) == 0:
                    # Check array length at +0x18 of entries array
                    alen = pm.read_int32(entries + 0x18)
                    # Heuristic: MTGA collection usually has > 100 cards
                    if 100 < alen < 100000:
                        cards_ptr = ptr_val
                        break
    
    if not cards_ptr:
        print("Could not identify Cards dictionary.")
        pm.close()
        return
        
    # 5. Read Dictionary
    entries_ptr = pm.read_ptr(cards_ptr + 0x18)
    count = pm.read_int32(cards_ptr + 0x20) # Count field
    
    print(f"Reading {count} cards from dictionary...")
    
    card_data = {}
    array_len = pm.read_int32(entries_ptr + 0x18)
    
    stride = 16 # Dictionary<int, int> Entry size is 16 bytes (4 ints)
    
    for i in range(array_len):
        base = entries_ptr + 0x20 + (i * stride)
        vals = pm.read_bytes(base, 16)
        if not vals: break
        hc, next_idx, key, value = struct.unpack('<iiii', vals)
        
        if key > 1000 and value > 0:
            card_data[key] = value
            
    pm.close()
    
    # --- Scryfall Conversion ---
    if not card_data:
        print("No cards found.")
        return

    print(f"Converting {len(card_data)} cards via Scryfall...")
    
    output_lines = []
    total = len(card_data)
    count = 0
    unknown_count = 0
    
    # Sort by ID for consistent output
    sorted_cards = sorted(card_data.items())
    
    for grp_id, owned in sorted_cards:
        count += 1
        try:
            url = f"https://api.scryfall.com/cards/arena/{grp_id}"
            req = urllib.request.Request(url, headers={'User-Agent': 'MTGA-Export-Py/1.0'})
            
            found = False
            for _ in range(3):
                try:
                    with urllib.request.urlopen(req, timeout=5) as response:
                        data = json.loads(response.read().decode())
                        name = data['name']
                        type_line = data.get('type_line', '')
                        
                        if 'Basic' in type_line:
                            print(f"[{count}/{total}] Skipping Basic Land: {name}")
                            found = True
                            break
                        
                        output_lines.append(f"{owned} {name}")
                        print(f"[{count}/{total}] {name}")
                        found = True
                        break
                except urllib.error.HTTPError as e:
                    if e.code == 429:
                        time.sleep(0.5)
                        continue
                    elif e.code == 404:
                        print(f"[{count}/{total}] Card {grp_id} not found.")
                        unknown_count += 1
                        found = True
                        break
                    else:
                        print(f"Error {e.code} for {grp_id}")
                        break
                except Exception as e:
                    print(f"Error for {grp_id}: {e}")
                    break
            
            if not found:
                output_lines.append(f"// {owned} ErrorCard_{grp_id}")

            time.sleep(0.05) 
            
        except Exception as e:
            print(f"Failed to process {grp_id}: {e}")

    if unknown_count > 0:
        output_lines.append(f"// Total Unknown Cards: {unknown_count}")
        print(f"Total Unknown Cards: {unknown_count}")

    filename = f"mtg_collection_{time.strftime('%Y%m%d')}.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    
    print(f"Done. Saved to {filename}")

if __name__ == '__main__':
    main()
