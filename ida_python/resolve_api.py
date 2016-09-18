import pefile, idautils, idc

DLLDIR = "/Users/joshstroschein/Desktop/BinaryNinja Work/Python Script/ida_python/dlls"

addr_resolve_module = 0x401728

# Modules to search for
modules = [
    "kernel32.dll",
    "advapi.dll",
    "ntdll.dll",
]

# Source: http://www.falatic.com/index.php/108/python-and-bitwise-rotation
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# Creates the hash based off of dll name
def create_module_hash(dll_name):
    result = 0x00000000

    for i in range(0,len(dll_name)):

        tmp = ord(dll_name[i])

        if tmp >= 0x41 or tmp < 0x5a:
            tmp = tmp | 0x20

        result = rol(result,7,32)
        result = result ^ tmp

    return result

#creates hash based off of WinAPI name (from Export directory->AddressOfNames)
def create_api_hash(export_name):
    api_hash = 0x00000000

    for i in range(0, len(export_name)):
        api_hash = rol(api_hash, 7, 32)
        api_hash = api_hash ^ ord(export_name[i])

    return api_hash

# This creates a hash from the list of potential modules to be compared
# against the hash used in the binary
def resolve_module_by_hash(module_hash):

    for dll in modules:

        result = create_module_hash(dll)

        if result == module_hash:

            return dll

    return None

# Once a DLL is identified, this checks an array of hashes to resolve the API calls
def resolve_module_apis(module_name, api_hash_src, api_hash_dst):

    #Load dll
    filename = os.path.join(DLLDIR, module_name)

    if not os.path.exists(filename):
        print "[!] ERROR Loading DLL"

    image_pe = pefile.PE(filename)
    api_hash = Dword(api_hash_src)

    while api_hash != 0xFFFF:

        for exp in image_pe.DIRECTORY_ENTRY_EXPORT.symbols:

            if not exp.name is None:

                api_hash_cmp = create_api_hash(exp.name)

                if api_hash == api_hash_cmp:
                    MakeComm(api_hash_dst, exp.name)
                    #@FIXME: conflicts in names
                    #MakeName(api_hash_dst, "HASH_" + exp.name)
                    api_hash_dst = api_hash_dst + 4

        api_hash_src = api_hash_src + 4
        api_hash = Dword(api_hash_src)

#Entry point, look for specific function call
for seg_ea in Segments():
    for function_ea in Functions(SegStart(seg_ea), SegEnd(seg_ea)):

        f_start = function_ea
        f_end = FindFuncEnd(function_ea)

        for head in Heads(f_start, f_end):

            if isCode(GetFlags(head)):
                if GetMnem(head) == 'call':

                    call_addr = GetOperandValue(head,0)

                    if call_addr == addr_resolve_module:

                        module_name = resolve_module_by_hash(GetOperandValue(idc.PrevHead(head),1))

                        if not module_name is None:
                            print "[*] Resolving calls for ", module_name

                            api_hashes = idc.NextHead(head)

                            api_hash_src = GetOperandValue(api_hashes,1)
                            api_hash_dst = GetOperandValue(idc.NextHead(api_hashes),1)

                            resolve_module_apis(module_name, api_hash_src, api_hash_dst)
