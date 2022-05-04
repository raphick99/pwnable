	• Can only insert ascii character.
	• I have 400 characters which I can enter. At offset 172 I need to put the return address to the beginning of my shellcode. Do I know where the stack is? So I can jump to 0x80000000. Then I execute my code from there. But my code needs to have the return address at offset 172, so I can use whats before or whats after.
	• 0x80000000 isnt ascii, therefore it may be my last opcodes. Meaning I will need to insert 0x80. Therefore, I have 168 bytes to work with.
	• How do I write 0x80000000? Its all non-ascii characters!!! Shyo. Maybe I need to write shellcode which will allocate to someplace else, and then run it. Doesn’t make sense. The first thing I am to write is a jump to somewhere. Therefore, this jump must be to 0x80000000, or someplace where I already have written my code to. 
	• Its statically linked. Therefore, maybe I can rop-jump once to something which will bring me back to 0x80000000. meaning I cal only override 3 bytes with something which helps me. Like jmp ecx or something.
	• I can rop to any gadget which contains 0x00. 
	• I cant insert int 0x80, because the assemby of that is \xcd\x80, which is 2 non-alphanumeric bytes. Therefore something else will be writing it.
	• By default, we return to 0x08048fcb from vuln
	• I control ebp, so maybe I need to overwrite the return address when returning from main, not vuln, because then I can control the stack. 
	• So I overwrite EBP in a way that the stack is someplace else. That other place needs to point to me. Could I put instructions? Probably. 
	• If I write 168 bytes, and then let the strcpy overwrite the last byte which goes into ebp, I make esp point to the stack section of the vuln function, which contains my alphanumeric stuff. Still doesn’t help me much, because I can only put alphanumeric stuff there, no code.
	• Run it a lot of times, until the stack comes out on the address which is already on the stack.
	• Maybe I need to put my rop-chain on the stack? Then somehow change ebp to point there.
By running a few times, and entering 168 bytes in a way which causes the last byte of ebp to be 0, I managed to jump to 0x80000000 because it is on the stack somewhere as an argument to a function. Now I need to figure out how to write alphanumeric opcodes.
