import sys, os, binaryninja, pefile, struct, binascii

DLLDIR = "/Users/joshstroschein/Library/Application Support/Binary Ninja/plugins/dlls"

addr_resolve_api = 0x40175e

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

            print "[!] Hash found for ", dll

            return dll

    return None

# Once a DLL is identified, this checks an array of hashes to resolve the API calls
def resolve_module_apis(view, function, module_name, api_hash_src, api_hash_dst):

    #Load dll
    filename = os.path.join(DLLDIR, module_name)

    if not os.path.exists(filename):
        print "[!] ERROR Loading DLL"

    image_pe = pefile.PE(filename)

    api_hash = view.read(api_hash_src, 4)
    api_hash = struct.unpack("<I", api_hash)[0]

    while api_hash != 0xFFFF:

        for exp in image_pe.DIRECTORY_ENTRY_EXPORT.symbols:

            if not exp.name is None:

                api_hash_cmp = create_api_hash(exp.name)

                if api_hash == api_hash_cmp:

                    view.define_auto_symbol(binaryninja.Symbol(binaryninja.FunctionSymbol, api_hash_dst, exp.name))
                    api_hash_dst = api_hash_dst + 4

        api_hash_src = api_hash_src + 4
        api_hash = view.read(api_hash_src, 4)
        api_hash = struct.unpack("<I", api_hash)[0]

def resolve_calls(view):

    #Skip _start, move to first func call
    main = view.get_function_at(view.platform, 0x404d53)

    for block in main.low_level_il:

        for il in block:

            if il.operation == binaryninja.core.LLIL_CALL:

                if hasattr(il.operands[0], 'value') and il.operands[0].value == addr_resolve_api:

                        il_module_hash = main.get_reg_value_at(view.arch, il.address, "ebx").value

                        module_name = resolve_module_by_hash(il_module_hash)

                        if not module_name is None:

                            main.set_comment(il.address, module_name)

                            #get the source/destination for the API hashes
                            api_hash_src = main.get_reg_value_at(view.arch, il.address, "esi").value
                            api_hash_dst = main.get_reg_value_at(view.arch, il.address, "edi").value

                            resolve_module_apis(view, main, module_name, api_hash_src, api_hash_dst)

binaryninja.PluginCommand.register("Resolve API Calls", "This determines API calls by module used.", resolve_calls)
