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

use reverie_api::remote::*;

use nix::unistd::Pid;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct RemoteRWLock {
    reader: HashSet<Pid>,
    writer: HashSet<Pid>,
    reverse_loopup_table: HashMap<u64, HashSet<Pid>>,
}

impl RemoteRWLock {
    pub fn new() -> Self {
        RemoteRWLock {
            reader: HashSet::new(),
            writer: HashSet::new(),
            reverse_loopup_table: HashMap::new(),
        }
    }
    pub fn try_read_lock(&mut self, tid: Pid, at: u64) -> bool {
        self.reader.insert(tid);
        let r = self.reverse_loopup_table.get(&at);

        if let Some(r) = r.filter(|r| !r.is_empty()) {
            for x in r {
                if self.writer.contains(&x) {
                    self.reader.remove(&tid);
                    return false;
                }
            }
        } else {
            self.writer.remove(&tid);
            self.reverse_loopup_table
                .entry(at)
                .and_modify(|s| {
                    s.insert(tid);
                })
                .or_insert({
                    let mut s = HashSet::new();
                    s.insert(tid);
                    s
                });
        }

        true
    }
    pub fn try_read_unlock(&mut self, tid: Pid, at: u64) -> bool {
        if !self.reader.contains(&tid) {
            return false;
        }
        if self.writer.contains(&tid) {
            return false;
        }
        self.reverse_loopup_table.entry(at).and_modify(|s| {
            let _ = s.remove(&tid);
        });
        true
    }

    pub fn try_write_lock(&mut self, tid: Pid, at: u64) -> bool {
        let r = self.reverse_loopup_table.get(&at);
        if r.is_none() || r.unwrap().is_empty() {
            self.writer.insert(tid);
            self.reader.remove(&tid);
            self.reverse_loopup_table
                .entry(at)
                .and_modify(|s| {
                    s.insert(tid);
                })
                .or_insert({
                    let mut s = HashSet::new();
                    s.insert(tid);
                    s
                });
            true
        } else {
            false
        }
    }

    pub fn try_write_unlock(&mut self, tid: Pid, at: u64) -> bool {
        if !self.writer.contains(&tid) {
            return false;
        }
        if self.reader.contains(&tid) {
            return false;
        }
        self.reverse_loopup_table.entry(at).and_modify(|s| {
            let _ = s.remove(&tid);
        });
        true
    }
}
