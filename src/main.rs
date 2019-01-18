
mod hooks;

fn main() {
    for hook in hooks::SYSCALL_HOOKS {
        println!("hook {}, len = {}", hook.symbol, hook.instructions.len());
    }
}
