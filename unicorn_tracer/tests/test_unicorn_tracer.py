import unittest
import os

from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32, UC_HOOK_INTR, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, \
    UC_X86_REG_EDX, UC_X86_REG_EIP
from unicorn_tracer import TracedUc

BASE_ADDR = 0x8048000
TEXT_ADDR = 0x8048080
DATA_ADDR = 0x8049124

STACK_ADDR = 0xfffdd000
STACK_SIZE = 0x21000

DIFFS = {392: {134512913L: 167}, 393: {134512913L: 97}, 394: {134512913L: 97}, 395: {134512913L: 97}, 396: {134512913L: 97}, 397: {134512913L: 97}, 398: {134512913L: 97}, 399: {134512913L: 97}, 400: {134512913L: 97}, 401: {134512913L: 97}, 408: {134512913L: 80}}



# callback for tracing Linux interrupt
def hook_intr(uc, intno, user_data):
    global id_gen

    # only handle Linux syscall
    if intno != 0x80:
        return

    eax = uc.reg_read(UC_X86_REG_EAX)
    ebx = uc.reg_read(UC_X86_REG_EBX)
    ecx = uc.reg_read(UC_X86_REG_ECX)
    edx = uc.reg_read(UC_X86_REG_EDX)
    eip = uc.reg_read(UC_X86_REG_EIP)

    # print(">>> INTERRUPT %d" % eax)

    if eax == 1:  # sys_exit
        print(">>> SYS_EXIT")
        uc.emu_stop()
    elif eax == 3:  # sys_read
        fd = ebx
        buf = ecx
        count = edx

        dummy_content = str("aaaaaaaaaa")
        if len(dummy_content) > count:
            dummy_content = dummy_content[:count]

        uc.mem_write(buf, dummy_content)

        msg = "read %d bytes from fd(%d) with dummy_content(%s)" % (count, fd, dummy_content)

        # fd_chains.add_log(fd, msg)
        print(">>> %s" % msg)
    elif eax == 4:  # sys_write
        fd = ebx
        buf = ecx
        count = edx

        content = uc.mem_read(buf, count)

        msg = "write data=%s count=%d to fd(%d)" % (content, count, fd)

        print(">>> %s" % msg)
        # fd_chains.add_log(fd, msg)


def read(name):
    with open(name, "rb") as f:
        return f.read()


def hook_code(uc, address, size, user_data):
    byte_value = uc.mem_read(0x8049188, 1)
    uc.mem_write(0x8049188, chr((byte_value[0] + 1) & 0xFF))

    byte_value = uc.mem_read(0x8049188 + 0x10, 1)
    uc.mem_write(0x8049188 + 0x10, chr((byte_value[0] + 1) & 0xFF))


class TestUnicornTracer(unittest.TestCase):

    def on_changes_detected(self, uc, code_address, memory_mapping, memory_image1, memory_image2):
        # print("At code addesss {}".format(hex(code_address)))
        #uc.get_terminal().print_differences_light(memory_mapping, memory_image1, memory_image2)

        current_diffs = memory_mapping.get_differences(memory_image1, memory_image2)

        for diff_offset in current_diffs:
            """
            if not diff_offset in DIFFS.keys():
                DIFFS[diff_offset] = dict()

            DIFFS[diff_offset][code_address] = current_diffs[diff_offset]
            """
            self.assertIn(diff_offset, DIFFS.keys(), "problem")
            self.assertIn(code_address, DIFFS[diff_offset].keys())
            self.assertNotEqual(DIFFS[diff_offset][code_address], current_diffs[diff_offset])

    def setUp(self):
        binary_path = os.path.join(os.getcwd(), "unicorn_tracer", "tests", "ch20.bin")

        self.mu = TracedUc(UC_ARCH_X86, UC_MODE_32)
        self.mu.add_changes_handler(self.on_changes_detected)

        self.mu.mem_map(0x8048000, 0x1000)
        memory_region = self.mu.mem_map(0x8049000, 0x1000, trace=True, continuous_tracing=False)
        memory_region.add_code_checkpoint(0x8048111L)

        self.mu.mem_map(0xf7ff9000, 0x3000)
        self.mu.mem_map(0xf7ffc000, 0x2000)
        self.mu.mem_map(0xfffdd000, 0x21000)

        self.mu.mem_write(BASE_ADDR, read(binary_path))
        self.mu.reg_write(UC_X86_REG_ESP, 0xfffdd000 + 0x21000 - 1)

        self.mu.hook_add(UC_HOOK_CODE, hook_code)
        self.mu.hook_add(UC_HOOK_INTR, hook_intr)

    def test_basic(self):
        self.mu.emu_start(TEXT_ADDR, TEXT_ADDR + 0x1000)


