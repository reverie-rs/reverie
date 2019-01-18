
mod hooks;

fn main() {
    let hooks = hooks::resolve_syscall_hooks_from("src/libsystrace.so").unwrap();
    for hook in hooks {
        println!("{:?}", hook);
    }
}
