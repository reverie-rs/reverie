
use std::collections::{HashMap, HashSet};
use nix::unistd::Pid;
use crate::remote::*;

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
        if r.is_none() || r.unwrap().len() == 0 {
            self.writer.remove(&tid);
            self.reverse_loopup_table.entry(at)
                .and_modify(|s| { s.insert(tid); })
                .or_insert( { let mut s = HashSet::new(); s.insert(tid); s} );
            true
        } else {
            for x in r.unwrap() {
                if self.writer.contains(&x) {
                    self.reader.remove(&tid);
                    return false;
                }
            }
            true
        }
    }
    pub fn try_read_unlock(&mut self, tid: Pid, at: u64) -> bool {
        if !self.reader.contains(&tid) {
            return false;
        }
        if self.writer.contains(&tid) {
            return false;
        }
        self.reverse_loopup_table.entry(at).and_modify(|s| { let _ = s.remove(&tid); });
        true
    }

    pub fn try_write_lock(&mut self, tid: Pid, at: u64) -> bool {
        let r = self.reverse_loopup_table.get(&at);
        if r.is_none() || r.unwrap().len() == 0 {
            self.writer.insert(tid);
            self.reader.remove(&tid);
            self.reverse_loopup_table.entry(at)
                .and_modify(|s| { s.insert(tid); })
                .or_insert({ let mut s = HashSet::new(); s.insert(tid); s});
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
        self.reverse_loopup_table.entry(at)
            .and_modify(|s| { let _ = s.remove(&tid); });
        true
    }
}
