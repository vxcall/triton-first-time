import lief
from triton import *
from functools import wraps

# Documentation
# ctx.getConcreteMemoryValue(MemoryAccess()) this combination represents dereference. specify the address and size of the memory to be accessed.
# for example, ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.esp)+0x4, CPUSIZE.DWORD)) is equivalent to *(DWORD*)(esp+4). which is an address of whatever value.
#
# getConcreteMemoryAreaValue is used to read memory from the specified address. requires address and size.

BINARY_PATH = './crackme.exe'
START_ADDR = 0x004011FA
END_ADDR = 0x0040120B

current_addr = 0
buffer_mem_add = 0x0
password_mem_add = 0x0

def load_binary(ctx: TritonContext, path):
    binary = lief.parse(path)
    sections = binary.sections
    for sec in sections:
        size = sec.virtual_size
        vaddr = sec.virtual_address + binary.optional_header.imagebase
        ctx.setConcreteMemoryAreaValue(vaddr, list(sec.content))
    return binary

def default_eax(ctx: TritonContext):
    return ctx.getConcreteRegisterValue(ctx.registers.eax)

def hook(func):
    @wraps(func)
    def wrapper(ctx: TritonContext, *args, **kwargs):
        global current_addr

        result = func(ctx, *args, **kwargs)

        # simulate ret
        # get and set return address
        esp = ctx.getConcreteRegisterValue(ctx.registers.esp)
        ret_addr = ctx.getConcreteMemoryValue(MemoryAccess(esp, CPUSIZE.DWORD))
        current_addr = ret_addr
        # add esp, sizeof(DWORD)
        ctx.setConcreteRegisterValue(ctx.registers.esp, esp + CPUSIZE.DWORD)

        # Set return value to eax
        ctx.setConcreteRegisterValue(ctx.registers.eax, result)

        print(f"[*] {func.__name__} hooked ! return -> {hex(ret_addr)}")

        return ret_addr

    return wrapper

@hook
def hook_lstrcmpA(ctx: TritonContext, buffer, password):
    global buffer_mem_add
    # I guess you can only symbolize memory 1 by 1 because MemoryAccess doesnt allow me to specify unaligned number of memory at once.
    for i in range(6):
        ctx.symbolizeMemory(MemoryAccess(ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.esp)+0x4, CPUSIZE.DWORD))+i, CPUSIZE.BYTE), "buffer")
    buffer_mem_add = MemoryAccess(ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.esp)+0x4, CPUSIZE.DWORD)), CPUSIZE.BYTE)
    if buffer == password.decode():
        return 0
    else:
        return 1

def get_memory_value(ctx: TritonContext, offset: int, size: int):
    return ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.esp) + offset, size))

def get_memory_area_value(ctx: TritonContext, offset: int, size: int):
    return ctx.getConcreteMemoryAreaValue(ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.esp) + offset, CPUSIZE.DWORD)), size)

def func_hooks(ctx: TritonContext, instruction: Instruction) -> bool:
    global password_mem_add
    j_lstrcmpA = 0x00401288
    if instruction.getAddress() == j_lstrcmpA:
        buffer = get_memory_value(ctx, 0x4, CPUSIZE.DWORD)
        password = get_memory_area_value(ctx, 0x8, 5)
        password_mem_add = MemoryAccess(get_memory_value(ctx, 0x8, CPUSIZE.DWORD), CPUSIZE.BYTE)
        hook_lstrcmpA(ctx, buffer, password)
        return True
    return False

def emulate(ctx: TritonContext, pc):
    global current_addr
    count = 0
    current_addr = pc
    while current_addr:

        opcode = ctx.getConcreteMemoryAreaValue(current_addr, 16)

        instruction = Instruction(current_addr, opcode)

        is_hook_executed = func_hooks(ctx, instruction)

        if not is_hook_executed:
            ctx.processing(instruction)
            current_addr = ctx.getConcreteRegisterValue(ctx.registers.eip)
            ctx.disassembly(instruction)
            print(instruction)

        if instruction.getAddress() == 0x0000401209:
            ast_ctx = ctx.getAstContext()
            # the 5 bytes buffer which I symbolized is equal to the password.
            # land is logical and. It's really a dirty way but idk how to do it better.
            model = ctx.getModel(ast_ctx.land([
                    ast_ctx.equal(ctx.getMemoryAst(buffer_mem_add), ctx.getMemoryAst(password_mem_add)),
                    ast_ctx.equal(ctx.getMemoryAst(MemoryAccess(buffer_mem_add.getAddress()+1, CPUSIZE.BYTE)), ctx.getMemoryAst(MemoryAccess(password_mem_add.getAddress()+1, CPUSIZE.BYTE))),
                    ast_ctx.equal(ctx.getMemoryAst(MemoryAccess(buffer_mem_add.getAddress()+2, CPUSIZE.BYTE)), ctx.getMemoryAst(MemoryAccess(password_mem_add.getAddress()+2, CPUSIZE.BYTE))),
                    ast_ctx.equal(ctx.getMemoryAst(MemoryAccess(buffer_mem_add.getAddress()+3, CPUSIZE.BYTE)), ctx.getMemoryAst(MemoryAccess(password_mem_add.getAddress()+3, CPUSIZE.BYTE))),
                    ast_ctx.equal(ctx.getMemoryAst(MemoryAccess(buffer_mem_add.getAddress()+4, CPUSIZE.BYTE)), ctx.getMemoryAst(MemoryAccess(password_mem_add.getAddress()+4, CPUSIZE.BYTE))),
                ]))
            sorted_model = dict(sorted(model.items()))
            print(sorted_model)

        count += 1
        if current_addr == END_ADDR:
            print("emulation end")
            print(f"total instruction count: {count}")
            return
    return

def setup_stack(ctx: TritonContext):
    ctx.setConcreteRegisterValue(ctx.registers.ebp, 0x100000)
    ctx.setConcreteRegisterValue(ctx.registers.esp, 0x100000)

if __name__ == '__main__':
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86)

    binary = load_binary(ctx, BINARY_PATH)

    ctx.setMode(MODE.ALIGNED_MEMORY, True)

    setup_stack(ctx)

    # Execute the function
    emulate(ctx, START_ADDR)