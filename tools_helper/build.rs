
fn main() {
    std::fs::copy("../src/consts.rs", "src/consts.rs").unwrap();
    std::fs::copy("../src/state.rs", "src/state.rs").unwrap();
}
