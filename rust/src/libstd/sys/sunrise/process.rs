use crate::ffi::OsStr;
use crate::fmt;
use crate::io::{self, Error, ErrorKind};
use crate::sys::fs::File;
use crate::sys::pipe::AnonPipe;
use crate::sys::unsupported;
use crate::sys_common::process::{CommandEnv, DefaultEnvKey};
use crate::sync::Arc;
use crate::vec::Vec;
use crate::string::String;

use sunrise_libuser::ldr::{ILoaderInterfaceProxy};

////////////////////////////////////////////////////////////////////////////////
// Command
////////////////////////////////////////////////////////////////////////////////

pub struct Command {
    program: String,
    args: Vec<String>,
    env: CommandEnv<DefaultEnvKey>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
}

// passed back to std::process with the pipes connected to the child, if any
// were requested
pub struct StdioPipes {
    pub stdin: Option<AnonPipe>,
    pub stdout: Option<AnonPipe>,
    pub stderr: Option<AnonPipe>,
}

pub enum Stdio {
    Inherit,
    Null,
    MakePipe,
}

impl Command {
    pub fn new(program: &OsStr) -> Command {
        Command {
            program: program.to_str().unwrap().to_owned(),
            args: Vec::new(),
            env: Default::default(),
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn arg(&mut self, arg: &OsStr) {
        self.args.push(arg.to_str().unwrap().to_owned());
    }

    pub fn env_mut(&mut self) -> &mut CommandEnv<DefaultEnvKey> {
        &mut self.env
    }

    pub fn cwd(&mut self, _dir: &OsStr) {
        unimplemented!()
    }

    pub fn stdin(&mut self, stdin: Stdio) {
        self.stdin = Some(stdin);
    }

    pub fn stdout(&mut self, stdout: Stdio) {
        self.stdout = Some(stdout);
    }

    pub fn stderr(&mut self, stderr: Stdio) {
        self.stderr = Some(stderr);
    }

    pub fn spawn(&mut self, _default: Stdio, _needs_stdin: bool)
        -> io::Result<(Process, StdioPipes)> {
        let interface = Arc::new(ILoaderInterfaceProxy::raw_new().expect("Cannot open a session with ILoaderInterface!"));

        let mut command_line_args: Vec<String> = self.args
            .iter()
            .map(|v| {
                let mut res = String::from("\"");

                res.push_str(v.as_str());
                res.push_str("\"");

                res
            })
            .collect();
        
        command_line_args.insert(0, self.program.clone());
        
        let command_line = command_line_args.join(" ");

        // TODO(Sunrise): Warn about pipes not being implemented
        let stdio_pipes = StdioPipes {
            stdin: None,
            stdout: None,
            stderr: None
        };

        // TODO(Sunrise): Remap error codes
        let pid = interface.launch_title(self.program.as_bytes(), command_line.as_bytes()).unwrap();

        let child = Process {
            pid,
            interface,
            result: None
        };

        Ok((child, stdio_pipes))
    }
}

impl From<AnonPipe> for Stdio {
    fn from(pipe: AnonPipe) -> Stdio {
        pipe.diverge()
    }
}

impl From<File> for Stdio {
    fn from(_file: File) -> Stdio {
        unimplemented!()
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

#[derive(Copy, Clone, PartialEq, Debug, Eq)]
pub struct ExitStatus(u32);

impl ExitStatus {
    pub fn success(&self) -> bool {
        self.0 == 0
    }

    pub fn code(&self) -> Option<i32> {
        if self.success() {
            None
        } else {
            Some(self.0 as i32)
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exit code: {}", self.0)
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct ExitCode(i32);

impl ExitCode {
    pub const SUCCESS: ExitCode = ExitCode(0);
    pub const FAILURE: ExitCode = ExitCode(1);

    pub fn as_i32(&self) -> i32 {
        self.0
    }
}

pub struct Process {
    pid: u64,
    interface: Arc<ILoaderInterfaceProxy>,
    result: Option<ExitStatus>
}

impl Process {
    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    pub fn kill(&mut self) -> io::Result<()> {
        if self.result.is_some() {
            Err(Error::new(ErrorKind::InvalidInput,
                           "invalid argument: can't kill an exited process"))
        } else {
            // TODO(Sunrise): We don't have a killed command :c
            unsupported()
        }
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let result_code = self.interface.wait(self.pid).expect("Unexpected error while waiting for process");
        let res = ExitStatus(result_code);

        self.result = Some(res);

        Ok(res)
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        // TODO(Sunrise): Implement this
        unsupported()
    }
}
