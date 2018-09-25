//! The scheduler

use spin::Mutex;
use alloc::sync::Arc;
use spin::RwLock;
use alloc::vec::Vec;

use ::process::{ProcessStruct, ProcessStructArc};

pub static SCHEDULE_QUEUE: Mutex<Vec<ProcessStructArc>> = Mutex::new(Vec::new());
