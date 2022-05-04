	• gets in write, will allow arbitrary buffer overflow to anywhere on the stack.
	• Mappings are created with WRX, meaning we can write any code.
	• The place where the mapping was placed is also printed. This means, if I manage to control execution flow, pwned.
	• Recursive call, we can exaust the stack
	• Case 0x31337, we get a 1 byte overflow. Since the function is fgets, we simply get to overwrite the last byte with NULL. This may simply modify the previous argument, I should see what is before this on the stack.
	• Off by one in the mem_arr. Seems like I can get access to somehting which cannot be mapped, in slot 256. meaning slot 256 is indeed in mem_arr, but cannot be allocated.
	• No ASLR. I know where the stack is. Or do i? do I somehow need to uncover this?
	• So I can write a lot to the stack using the recursive funciton. Then I can write a lot to the heap using the buffer overflow
	• Stack if breaking on entry-point is 0xffffdcc0. Since ASLR is disabled, this should persist.
	• If the random number generator generates anything larger than the stack, we should get an integer overflow, which will cause the mmap to 0x00000000 ( I think with brute force this can be caused)
	• Keep creating mappings until I am close enough to the stack. Then cause the stack to get there, and then write to the note. 
	• After 5679 the remote running pwn failed. Probably stack overflow. Dmesg said it failed at 0xff44cd80. Therefore, the stack size is less than 0xbb0280.
	• Beginning of select_menu stack: 0xffffd05c. Next call to select_menu: 0xffffcc2c. Meaning its incremented each time by 1072:
		○ 4 for call to function
		○ 4 for ebp
		○ 1064 for stack variables (mostly goes to buffer with 1024 bytes)
	• The problem with this is that if the stack tries to resize, as it will, it will fail because of our mapping. So we sort of need to get close enough, and that’s it. How do I know what close enough is? I guess based on how much stack is already used.
It worked!!! Need to figure out how to finish it, but very cool
