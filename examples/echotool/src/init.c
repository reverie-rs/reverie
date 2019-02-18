
// Provided by this systrace tool (.so):
extern long captured_syscall(int, long, long, long, long, long, long);

// Provided by the underlying instrumenation library:
extern long untraced_syscall(int, long, long, long, long, long, long);

// An initialization function for this systrace tool (.so):
__attribute__((constructor)) static void __echotool_early_init(void) {
	unsigned long* hook_addr = (unsigned long*)0x70001028UL;
	*hook_addr = (unsigned long)&captured_syscall;
}
