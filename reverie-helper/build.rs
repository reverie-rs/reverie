/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * 
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

use std::io::Result;

fn main() -> Result<()> {
    cc::Build::new()
        .define("_POSIX_C_SOURCE", "20180920")
        .define("_GNU_SOURCE", "1")
        .define("USE_SAVE", "1")
        .flag("-fPIC")
        .include("../include")
        .include("./src")
        .file("./src/trampoline.S")
        .file("./src/raw_syscall.S")
        .file("./src/remote_call.S")
        .compile("my-trampoline");

    Ok(())
}
