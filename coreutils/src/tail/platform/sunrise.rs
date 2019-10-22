pub type Pid = usize;

pub struct ProcessChecker {
    pid: self::Pid,
}

impl ProcessChecker {
    pub fn new(process_id: self::Pid) -> ProcessChecker {
        ProcessChecker { pid: process_id }
    }

    // Borrowing mutably to be aligned with Windows implementation
    pub fn is_dead(&mut self) -> bool {
        // not availaible on Sunrise
        true
    }
}

pub fn supports_pid_checks(pid: self::Pid) -> bool {
    false
}