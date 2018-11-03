import unittest

from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32, UC_HOOK_INTR
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, \
UC_X86_REG_EDX, UC_X86_REG_EIP
from unicorn_tracer import TracedUc

BASE_ADDR=0x8048000
TEXT_ADDR=0x8048080
DATA_ADDR=0x8049124

STACK_ADDR = 0xfffdd000
STACK_SIZE = 0x21000



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

        dummy_content = str("a")
        if len(dummy_content) > count:
            dummy_content = dummy_content[:count]

        uc.mem_write(buf, dummy_content)

        msg = "read %d bytes from fd(%d) with dummy_content(%s)" % (count, fd, dummy_content)

        #fd_chains.add_log(fd, msg)
        print(">>> %s" % msg)
    elif eax == 4:  # sys_write
        fd = ebx
        buf = ecx
        count = edx

        content = uc.mem_read(buf, count)

        msg = "write data=%s count=%d to fd(%d)" % (content, count, fd)

        print(">>> %s" % msg)
        #fd_chains.add_log(fd, msg)


def read(name):
    with open(name, "rb") as f:
        return f.read()


class UnicornTracerTest(unittest.TestCase):

    @classmethod
    def setUp(self):
        self.mu = TracedUc(UC_ARCH_X86, UC_MODE_32)

    def test_basic(self):
        self.mu.mem_map(0x8048000, 0x1000)
        self.mu.mem_map(0xf7ff9000, 0x3000)
        self.mu.mem_map(0x8049000, 0x1000, trace=True)
        self.mu.mem_map(0xf7ffc000, 0x2000)
        self.mu.mem_map(0xfffdd000, 0x21000)

        self.mu.mem_write(BASE_ADDR, read("e:/workspaces/python/unicorn_tracer/tests/ch20.bin"))
        self.mu.reg_write(UC_X86_REG_ESP, 0xfffdd000 + 0x21000 - 1)

        self.mu.hook_add(UC_HOOK_INTR, hook_intr)

        self.mu.emu_start(TEXT_ADDR, TEXT_ADDR + 0x1000)

        print(">>> Emulation done.")