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

use std::io;

use cc;

fn main() -> io::Result<()> {
    cc::Build::new()
        .flag("-D_GNU_SOURCE=1")
        .file("src/dl_ns.c")
        .compile("my-asm-lib");
    Ok(())
}
