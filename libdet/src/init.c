extern long captured_syscall(int, long, long, long, long, long, long);
extern long untraced_syscall(int, long, long, long, long, long, long);

__attribute__((constructor)) static void __libdet_early_init(void) {
	unsigned long* hook_addr = (unsigned long*)0x70001028UL;
	*hook_addr = (unsigned long)&captured_syscall;
}
