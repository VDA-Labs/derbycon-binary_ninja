import sys, os, binaryninja, pefile, struct, binascii

addr_resolve_api = 0x40175E
addr_resolve_module = 0x401728

DLLDIR = "/Users/joshstroschein/Library/Application Support/Binary Ninja/plugins/dlls"

# Modules to search for
modules = [
    "kernel32.dll",
    "advapi.dll",
    "ntdll.dll",
]

# Rotate left: 0b1001 --> 0b0011
# Source: http://www.falatic.com/index.php/108/python-and-bitwise-rotation
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

#Creates the hash based off of dll name
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
def resolve_modules(module_hash):

    for dll in modules:

        result = create_module_hash(dll)

        if result == module_hash:

            print "[!] Hash found for ", dll

            return dll

    return None

# Once a DLL is identified, this checks an array of hashes to resolve the API calls
def resolve_module_apis(view, function, dll_name, api_hash_src, api_hash_dst):

    #Load dll
    filename = os.path.join(DLLDIR, dll_name)

    if not os.path.exists(filename):
        print "[!] ERROR Loading DLL"

    image_pe = pefile.PE(filename)

    #FIXME: need to refactor this
    api_hash = view.read(api_hash_src, 4)
    api_hash = binascii.hexlify(api_hash)
    api_hash = int(api_hash, 16)
    api_hash = struct.unpack("<I", struct.pack(">I", api_hash))[0]

    while api_hash != 0xFFFF:

        for exp in image_pe.DIRECTORY_ENTRY_EXPORT.symbols:

            if not exp.name is None:

                hash_cmp = create_api_hash(exp.name)

                if hex(api_hash) == hex(hash_cmp):
                    #FIXME: doesn't work? That is, can't comment in a data section?
                    #function.set_comment(api_hash_dst, "josh")

                    view.define_auto_symbol(binaryninja.Symbol(binaryninja.FunctionSymbol, api_hash_dst, exp.name))
                    #print data_sym, hex(api_hash_dst)

                    api_hash_dst = api_hash_dst + 4

        #FIXME: this can't be the way to do this :(
        api_hash_src = api_hash_src + 4
        api_hash = view.read(api_hash_src, 4)
        api_hash = binascii.hexlify(api_hash)
        api_hash = int(api_hash, 16)
        api_hash = struct.unpack("<I", struct.pack(">I", api_hash))[0]

def resolve_calls(view):

    print "[*] Analyzing Sample..."

    #Skip _start, move to first func call
    main = view.get_function_at(view.platform, 0x404d53)

    for block in main.low_level_il:

        prev_il = []
        il_index = 0

        for il in block:

            if il.operation == binaryninja.core.LLIL_CALL:

                #TODO: If the operand is a register, the 'value' attribute is not present
                if hasattr(il.operands[0], 'value') and il.operands[0].value == addr_resolve_api:

                    #Get instruction before
                    if len(prev_il) > 5:
                        il_module_hash = prev_il[il_index-6]

                        module_name = resolve_modules(il_module_hash.operands[1].value)

                        if not module_name is None:

                            main.set_comment(il_module_hash.address, module_name)

                            #get the hashes
                            api_src_hash = prev_il[il_index - 4].operands[1].value

                            api_dst_hash = prev_il[il_index - 3].operands[1].value

                            resolve_module_apis(view, main, module_name, api_src_hash, api_dst_hash)

                            break

            #FIXME: need to look into other ways to navigate previous instructions from current instruction/IL
            prev_il.append(il)
            il_index = il_index + 1

binaryninja.PluginCommand.register("Resolve Module Hash", "This determines the desired module by hash value used", resolve_calls)
