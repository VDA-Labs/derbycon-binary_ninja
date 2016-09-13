import sys, os, pefile, struct
from binascii import hexlify

try:
    import binaryninja
except ImportError:
    sys.path.append("/Applications/Binary Ninja.app/Contents/Resources/python/")
import binaryninja

addr_resolve_module = 0x401728
addr_resolve_api = 0x40175e
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
def resolve_apis(view, dll_name, api_hash_src, api_hash_dst):

    #Load dll
    filename = os.path.join(DLLDIR, dll_name)

    if not os.path.exists(filename):
        print "[!] ERROR Loading DLL"

    image_pe = pefile.PE(filename)

    #api_hash = Dword(api_hash_src)
    api_hash = view.read(api_hash_src, 4)
    api_hash = hexlify(api_hash)
    api_hash = int(api_hash, 16)
    api_hash = struct.unpack("<I", struct.pack(">I", api_hash))[0]

    while api_hash != 0xFFFF:

        for exp in image_pe.DIRECTORY_ENTRY_EXPORT.symbols:

            if not exp.name is None:

                hash_cmp = create_api_hash(exp.name)
                #print "[!] comparing ", hex(api_hash), " to ", hex(hash_cmp)
                if hex(api_hash) == hex(hash_cmp):
                    #MakeComm(api_hash_dst, exp.name)
                    print "[*] API Found ", exp.name
                    api_hash_dst = api_hash_dst + 4

        #FIXME: this can't be the way to do this :(
        api_hash_src = api_hash_src + 4
        api_hash = view.read(api_hash_src, 4)
        api_hash = hexlify(api_hash)
        api_hash = int(api_hash, 16)
        api_hash = struct.unpack("<I", struct.pack(">I", api_hash))[0]

def analysis_complete():
    print "[*] Analysis Complete"

#Get the file
filename = "dumped.bin"

if not os.path.exists(filename):
    print "[!] ERROR Loading sample"

#Open Binary For Analysis
print "[*] Analyzing Sample..."

bv = binaryninja.BinaryViewType["PE"].open(filename)

#Callback?
bv.add_analysis_completion_event(analysis_complete)

#Auto-analysis does not start automatically - consider update_analysis() to send to background
bv.update_analysis_and_wait()

#Skip _start, move to first func call
main = bv.get_function_at(bv.platform, 0x404d53)

for block in main.low_level_il:

    prev_il = []
    il_index = 0

    for il in block:

        if il.operation == binaryninja.core.LLIL_CALL:

            if hasattr(il.operands[0], 'value') and il.operands[0].value == addr_resolve_api:

                #Get instruction before
                if len(prev_il) > 5:
                    il_hash = prev_il[il_index-6].operands[1].value

                    module_name = resolve_modules(il_hash)

                    if not module_name is None:
                        #get the hashes
                        api_src_hash = prev_il[il_index - 4].operands[1].value

                        api_dst_hash = prev_il[il_index - 3].operands[1].value

                        resolve_apis(bv, module_name, api_src_hash, api_dst_hash)

                        symbols = bv.get_symbols_of_type("DataType", 0x4050dc, 0x405128)


                        break

        #prev_len = bv.get_instruction_length(bv.arch, il.address)
        prev_il.append(il)
        il_index = il_index + 1
