import sys, os, binaryninja

addr_resolve_module = 0x401728
DLLDIR = "dlls"

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

# This creates a hash from the list of potential modules to be compared
# against the hash used in the binary
def resolve_modules(module_hash):

    for dll in modules:

        result = create_module_hash(dll)

        if result == module_hash:

            print "[!] Hash found for ", dll

            return dll

    return None

def resolve_apis(view):

    print "[*] Analyzing Sample..."

    #Skip _start, move to first func call
    main = view.get_function_at(view.platform, 0x404d53)

    prev_len = 0

    for block in main.low_level_il:

        prev_il = []
        instr_index = 0

        for il in block:

            if il.operation == binaryninja.core.LLIL_CALL:

                #TODO: If the operand is a register, the 'value' attribute is not present
                if hasattr(il.operands[0], 'value') and il.operands[0].value == addr_resolve_module:

                    #Get instruction before
                    il_hash = prev_il[instr_index-1].operands[1].value

                    module_name = resolve_modules(il_hash)

                    if not module_name is None:
                        main.set_comment(il.address, module_name)

                        





            prev_il.append(il)
            instr_index = instr_index + 1




binaryninja.PluginCommand.register("Resolve Module Hash", "This determines the desired module by hash value used", resolve_apis)
