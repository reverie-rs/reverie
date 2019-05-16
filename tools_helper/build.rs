
fn main() {
    std::fs::copy("../src/consts.rs", "src/consts.rs").unwrap();
    std::fs::copy("../src/local_state.rs", "src/local_state.rs").unwrap();
}
