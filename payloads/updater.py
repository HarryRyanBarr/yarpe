import struct

WRITING = False

if WRITING:  # dummy objects for writing code
    nogc = []

    class Container:
        def __getattribute__(self, name):
            return Executable()

    class sc:
        mem = bytearray()
        version = ""
        platform = ""
        errno = 0
        libkernel_addr = 0
        libc_addr = 0
        exec_addr = 0

        syscalls = Container()
        functions = Container()

        @staticmethod
        def make_function_if_needed(name, addr):
            return Executable()

        @staticmethod
        def get_current_ip():
            return ""

    class ROPChain:
        def __init__(self, *args, **kwargs):
            pass

        def push_syscall(self, *args, **kwargs):
            pass

        def push_write_into_memory(self, *args, **kwargs):
            pass

        def append(self, *args, **kwargs):
            pass

        def reset(self):
            pass

    class Executable:
        errno = 0
        chain = ROPChain(sc)

        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, *args, **kwargs):
            return 0

        def get_error_string(self):
            return ""

        def setup_front_chain(self):
            pass

        def setup_syscall_chain(self, *args, **kwargs):
            pass

        def setup_post_chain(self):
            pass

        def setup_back_chain(self):
            pass

        def execute(self):
            return 0

    SYSCALL = {}
    LIBC_OFFSETS = {}
    SELECTED_LIBC = {}

    def alloc(size):
        return bytearray(size)

    def readuint(addr, size):
        return 0

    def get_ref_addr(data):
        return 0

    def readbuf(addr, size):
        return bytearray(size)

    def get_cstring(data, addr=0):
        return ""

    def u64_to_i64(value):
        return value

    class SocketError(Exception):
        pass

    AF_INET = 0
    SOCK_STREAM = 0
    SOL_SOCKET = 0
    SO_REUSEADDR = 0

    port = 0
    s = 0
    sockaddr_in = bytearray()
    len_buf = bytearray()


UPDATE_SIZE = 1024 * 1024 * 1  # 1 MB
UPDATE_BUF = alloc(UPDATE_SIZE)

ip = sc.get_current_ip()

if ip is None:
    print("Send updated save file to port %d" % (port))
else:
    print("Send updated save file to %s:%d" % (ip, port))

print("Waiting for client connection...")
client_sock = u64_to_i64(
    sc.syscalls.accept(
        s,
        sockaddr_in,
        len_buf,
    )
)
if client_sock < 0:
    raise SocketError(
        "accept failed with return value %d, error %d\n%s"
        % (
            client_sock,
            sc.syscalls.accept.errno,
            sc.syscalls.accept.get_error_string(),
        )
    )

print("Client connected on socket %d" % client_sock)

read_size = -1
update_file = b""
while read_size != 0:
    read_size = u64_to_i64(
        sc.syscalls.read(
            client_sock,
            UPDATE_BUF,
            UPDATE_SIZE,
        )
    )
    update_file += UPDATE_BUF[:read_size]
    if read_size < 0:
        raise SocketError(
            "read failed with return value %d, error %d\n%s"
            % (
                read_size,
                sc.syscalls.read.errno,
                sc.syscalls.read.get_error_string(),
            )
        )

print("Received updated save file, size %d bytes" % len(update_file))
sc.syscalls.close(client_sock)
with open("/saves/1-1-LT1.save", "wb") as f:
    f.write(update_file)
print("Saved updated save file to /saves/1-1-LT1.save")
print("Press X(or O) to exit the game(by crashing it).{w}")
exit(0)
