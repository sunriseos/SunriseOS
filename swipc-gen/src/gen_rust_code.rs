//! Code generation implementation
//!
//! Entrypoint is [generate_ipc].

use lazy_static::lazy_static;

use std::fmt::Write;
use std::collections::HashMap;
use swipc_parser::{Alias, Func, KHandleType, TypeDef, Type, Decorator};
use bit_field::BitField;

lazy_static! {
    static ref BUILTINS: HashMap<&'static str, (u8, &'static str)> = {
        let mut types = HashMap::new();
        types.insert("bool", (1, "bool"));
        types.insert("u8", (1, "u8"));
        types.insert("i8", (1, "i8"));
        types.insert("u16", (2, "u16"));
        types.insert("u32", (4, "u32"));
        types.insert("i32", (4, "i32"));
        types.insert("f32", (4, "f32"));
        types.insert("u64", (8, "u64"));
        types.insert("i64", (8, "i64"));
        types.insert("u128", (16, "u128"));
        types.insert("uint8_t", (1, "u8"));
        types
    };
}

/// Returns true if the given pattern matches, false otherwise.
///
/// # Examples
///
/// ```rust
/// assert!(matches!(let 0..4 = 3) == true);
/// assert!(matches!(let Option::Some(_) = None) == false);
/// assert!(matches!(let "test" = "test") == true);
/// ```
macro_rules! matches {
    (let $pat:pat = $x:expr) => { if let $pat = $x { true } else { false } };
}

/// Internal error type. Raised whenever we fail to generate something, so we
/// can carry on generating everything else.
#[derive(Debug)]
enum Error {
    /// This generation unit contains an unsupported type. We should skip it.
    UnsupportedStruct,
}

/// Checks if an alias contains a raw data type (as opposed to a special
/// datatype)
fn is_raw(val: &Alias) -> bool {
    match val {
        Alias::Bytes(_) | Alias::Align(_, _) | Alias::Other(_) => true,
        _ => false
    }
}

/// Takes an iterator of potentially unnamed arguments/returns, and returns a
/// named version (where the unnamed fields are named unknown_idx).
fn named_iterator<'a, I>(it: I, is_output: bool) -> impl Iterator<Item = (&'a Alias, String)>
where
    I: IntoIterator<Item = &'a (Alias, Option<String>)>
{
    it.into_iter().filter(move |(ty, _)| {
        match ty {
            Alias::Array(..) | Alias::Buffer(..) => !is_output,
            _ => true,
        }
    }).enumerate().map(|(idx, (v, name))| {
        (v, name.clone().unwrap_or_else(|| format!("unknown_{}", idx)))
    })
}

/// Creates an iterator over the raw values from an argument/ret iterator.
fn raw_iterator<'a, I>(it: I, is_output: bool) -> impl Iterator<Item = (&'a Alias, String)>
where
    I: IntoIterator<Item = &'a (Alias, Option<String>)>,
{
    named_iterator(it, is_output).filter(|(v, _name)| is_raw(v))
}

/// Format the arguments of a function.
///
/// Return buffers are also formatted in this function, since they will be passed
/// as mutable references to the function in the generated rust code.
///
/// Returns a coma separated list of `name: rust_type`.
///
/// See [get_type] to find the mapping of a SwIPC type to a Rust type.
fn format_args(args: &[(Alias, Option<String>)], ret: &[(Alias, Option<String>)]) -> Result<String, Error> {
    let mut arg_list = Vec::new();
    for (idx, (ty, name)) in args.iter().chain(ret.iter().filter(|(ty, _)| {
        match ty { Alias::Array(..) | Alias::Buffer(..) => true, _ => false }
    })).enumerate()
    {
        let mut s = String::new();
        if let Alias::Pid = ty {
            continue;
        }
        match name.as_ref().map(|v| &**v) {
            // TODO: More thorough keyword sanitizer in swipc generator.
            // BODY: The SwIPC generator does little to no sanitizing of argument
            // BODY: names that may be keywords in rust. We should have a list of
            // BODY: keywords and a central function to fix them up.
            // Rename type to ty since type is a keyword in rust.
            Some("type") => s += "ty",
            Some(name) => s += name,
            None => s += &format!("unknown_{}", idx)
        }
        s += ": ";
        s += &get_type(idx >= args.len(), ty)?;
        arg_list.push(s);
    }
    Ok(arg_list.join(", "))
}

/// Format the return type of a function.
///
/// - If there's 0 return types, then the return type will be ().
/// - If there's only 1 return type, then that type will be passed directly as
///   the return type.
/// - If there's 2 or more arguments, then the return type will be a tuple of
///   those types.
///
/// IPC Buffers are skipped from the return types, since they are handled by the
/// argument formatter instead. Buffers are passed as mutable reference
/// arguments.
///
/// See [get_type] to find the mapping of a SwIPC type to a Rust type.
fn format_ret_ty(ret: &[(Alias, Option<String>)]) -> Result<String, Error> {
    let mut v = Vec::new();

    for (ty, _name) in named_iterator(ret, true) {
        v.push(get_type(true, ty)?);
    }

    match v.len() {
        0 => Ok("()".to_string()),
        1 => Ok(v[0].clone()),
        _ => Ok(format!("({})", v.join(", ")))
    }
}

/// Get the Rust equivalent of a handle type.
///
/// If no equivalent exist or are supported yet, None is returned. The full path
/// should be returned.
fn get_handle_type(ty: &Option<KHandleType>) -> Option<&'static str> {
    match ty {
        Some(KHandleType::ClientSession) => Some("sunrise_libuser::types::ClientSession"),
        Some(KHandleType::ServerSession) => Some("sunrise_libuser::types::ServerSession"),
        Some(KHandleType::ClientPort)    => Some("sunrise_libuser::types::ClientPort"),
        Some(KHandleType::ServerPort)    => Some("sunrise_libuser::types::ServerPort"),
        Some(KHandleType::SharedMemory)  => Some("sunrise_libuser::types::SharedMemory"),
        _                                => None
    }
}

/// Generate code to recover a single return value from an output Message.
fn format_ret(ret: (&Alias, String)) -> Result<String, Error> {
    match ret.0 {
        Alias::Object(ty) => Ok(format!("{}::from(ClientSession(res.pop_handle_move()?))", ty)),
        Alias::KObject => Ok("res.pop_handle_move()?".to_string()),
        Alias::KHandle(is_copy, ty) => if let Some(s) = get_handle_type(ty) {
            Ok(format!("{}(res.pop_handle_{}()?)", s, if *is_copy { "copy" } else { "move" }))
        } else {
            Ok(format!("res.pop_handle_{}()?", if *is_copy { "copy" } else { "move" }))
        },
        Alias::Pid => Ok("res.pop_pid()?".to_string()),
        Alias::Bytes(..) |
        Alias::Align(..) |
        Alias::Other(..) => Ok(format!("res.raw().{}", ret.1)),
        _ => unreachable!()
    }
}

/// Get the Rust type of an [Alias]. If output is true, then the type should be
/// suitable for a return type (or an output IPC buffer argument). If output is
/// false, then the type should be suitable for an input argument.
fn get_type(output: bool, ty: &Alias) -> Result<String, Error> {
    let is_mut = if output { "mut " } else { "" };
    match ty {
        // actually a special kind of buffer
        Alias::Array(underlying, _) => Ok(format!("&{}[{}]", is_mut, get_type(output, underlying)?)),

        // Blow up if we don't know the size or type
        Alias::Buffer(box Alias::Other(name), _, 0) if name == "unknown" => Err(Error::UnsupportedStruct),
        // Treat unknown but sized types as an opaque byte array
        Alias::Buffer(box Alias::Other(name), _, size) if name == "unknown" => Ok(format!("&{}[u8; {:#x}]", is_mut, size)),
        // 0-sized buffer means it takes an array
        Alias::Buffer(inner @ box Alias::Other(_), _, 0) => Ok(format!("&{}[{}]", is_mut, get_type(output, inner)?)),
        // Typed buffers are just references to the underlying raw object
        Alias::Buffer(inner @ box Alias::Bytes(_), _, _) |
        Alias::Buffer(inner @ box Alias::Other(_), _, _) => Ok(format!("&{}{}", is_mut, get_type(output, inner)?)),
        // Panic if we get a buffer with an unsupported underlying type.
        Alias::Buffer(underlying, _, _) => panic!("Buffer with underlying type {:?}", underlying),

        Alias::Object(name) => Ok(name.clone()),

        // Unsized bytes
        Alias::Bytes(0) => Ok("[u8]".to_string()),
        Alias::Bytes(len) => Ok(format!("[u8; {}]", len)),

        // Deprecated in newer version of SwIPC anyways.
        Alias::Align(_alignment, _underlying) => Err(Error::UnsupportedStruct),

        Alias::KObject => Ok("Handle".to_string()),
        Alias::KHandle(is_copy, ty) => if let Some(s) = get_handle_type(ty) {
            Ok(format!("{}{}", if *is_copy && !output { "&" } else { "" }, s))
        } else {
            Ok(format!("sunrise_libuser::types::{}", if *is_copy && !output { "HandleRef" } else { "Handle" }))
        },
        Alias::Pid => Ok("u64".to_string()),
        Alias::Other(ty) if ty == "unknown" => Err(Error::UnsupportedStruct),
        Alias::Other(ty) => Ok(ty.clone()),
    }
}

/// Generate code for a single function.
fn format_cmd(cmd: &Func) -> Result<String, Error> {
    let mut s = String::new();
    for line in cmd.doc.lines() {
        writeln!(s, "    /// {}", line).unwrap();
    }
    writeln!(s, "    pub fn {}(&mut self, {}) -> Result<{}, Error> {{", &cmd.name, format_args(&cmd.args, &cmd.ret)?, format_ret_ty(&cmd.ret)?).unwrap();
    writeln!(s, "        use sunrise_libuser::ipc::Message;").unwrap();
    writeln!(s, "        let mut buf = [0; 0x100];").unwrap();
    writeln!(s).unwrap();
    let in_raw = if cmd.args.iter().any(|(argty, _)| is_raw(argty)) {
        writeln!(s, "        #[repr(C)]").unwrap();
        writeln!(s, "        #[derive(Clone, Copy, Default)]").unwrap();
        writeln!(s, "        #[allow(clippy::missing_docs_in_private_items)]").unwrap();
        writeln!(s, "        struct InRaw {{").unwrap();
        for (argty, argname) in raw_iterator(&cmd.args, false) {
            writeln!(s, "            {}: {},", argname, get_type(false, argty)?).unwrap();
        }
        writeln!(s, "        }}").unwrap();
        "InRaw"
    } else {
        "()"
    };


    let ipc_count = cmd.args.iter().chain(&cmd.ret).filter(|(argty, _)| match argty {
        Alias::Array(..) | Alias::Buffer(..) => true,
        _ => false
    }).count();
    let handle_move_count = cmd.args.iter().filter(|(argty, _)| match argty {
        Alias::KObject | Alias::KHandle(false, _) | Alias::Object(_) => true,
        _ => false
    }).count();
    let handle_copy_count = cmd.args.iter().filter(|(argty, _)| match argty {
        Alias::KHandle(true, _) => true,
        _ => false
    }).count();

    writeln!(s, "        let mut msg = Message::<{}, [_; {}], [_; {}], [_; {}]>::new_request(None, {});",
             in_raw, ipc_count, handle_copy_count, handle_move_count, cmd.num).unwrap();

    if cmd.args.iter().any(|(argty, _)| is_raw(argty)) {
        writeln!(s, "        msg.push_raw(InRaw {{").unwrap();
        for (_argty, argname) in raw_iterator(&cmd.args, false) {
            writeln!(s, "            {},", argname).unwrap();
        }
        writeln!(s, "        }});").unwrap();
    }

    for (idx, (argty, argname)) in cmd.args.iter().chain(cmd.ret.iter().filter(|(argty, _)| match argty {
        Alias::Array(..) | Alias::Buffer(..) => true, _ => false
    })).enumerate()
    {
        let argname = argname.clone().unwrap_or_else(|| format!("unknown_{}", idx));
        match argty {
            Alias::Array(_alias, _)                    => return Err(Error::UnsupportedStruct),
            Alias::Buffer(_alias, ty, _)               => {
                match (ty.get_bits(0..2), ty.get_bits(2..4), ty.get_bit(5)) {
                    // A Buffer
                    (1, 1, false) => return Err(Error::UnsupportedStruct),
                    // B Buffer
                    (2, 1, false) => return Err(Error::UnsupportedStruct),
                    // X Buffer
                    (1, 2, false) => writeln!(s, "        msg.push_out_pointer({});", argname).unwrap(),
                    // C Buffer
                    (2, 2, false) => writeln!(s, "        msg.push_in_pointer({}, {});", argname, !ty.get_bit(4)).unwrap(),
                    // Smart A+X
                    (1, 0, true) => return Err(Error::UnsupportedStruct),
                    // Smart B+C
                    (2, 0, true) => return Err(Error::UnsupportedStruct),
                    _ => panic!("Illegal buffer type: {}", ty)
                }
            },
            Alias::Object(_)                          => writeln!(s, "        msg.push_handle_move({}.into());", argname).unwrap(),
            Alias::KHandle(false, ty) if get_handle_type(ty).is_some() =>
                writeln!(s, "        msg.push_handle_move({}.0);", argname).unwrap(),
            Alias::KHandle(false, _) =>
                writeln!(s, "        msg.push_handle_move({});", argname).unwrap(),
            Alias::KHandle(true, ty) if get_handle_type(ty).is_some() =>
                writeln!(s, "        msg.push_handle_copy({}.0.as_ref());", argname).unwrap(),
            Alias::KHandle(true, _) =>
                writeln!(s, "        msg.push_handle_copy({});", argname).unwrap(),
            Alias::KObject                            => writeln!(s, "        msg.push_handle_move({});", argname).unwrap(),
            Alias::Pid                                => writeln!(s, "        msg.send_pid(None);").unwrap(),
            _                                         => continue,
        }
    }

    writeln!(s, "        msg.pack(&mut buf[..]);").unwrap();
    writeln!(s, "        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;").unwrap();


    // TODO: Handle return C buffers.
    let ipc_count = 0;
    let handle_move_count = cmd.ret.iter().filter(|(argty, _)| match argty {
        Alias::KObject | Alias::KHandle(false, _) | Alias::Object(_) => true,
        _ => false
    }).count();
    let handle_copy_count = cmd.ret.iter().filter(|(argty, _)| match argty {
        Alias::KHandle(true, _) => true,
        _ => false
    }).count();

    writeln!(s).unwrap();
    let out_raw = if cmd.ret.iter().any(|(argty, _)| is_raw(argty)) {
        writeln!(s, "        #[repr(C)]").unwrap();
        writeln!(s, "        #[derive(Clone, Copy, Default)]").unwrap();
        writeln!(s, "        #[allow(clippy::missing_docs_in_private_items)]").unwrap();
        writeln!(s, "        struct OutRaw {{").unwrap();
        for (argty, argname) in raw_iterator(&cmd.ret, true) {
            writeln!(s, "            {}: {},", argname, get_type(true, argty)?).unwrap();
        }
        writeln!(s, "        }}").unwrap();
        "OutRaw"
    } else {
        "()"
    };

    writeln!(s, "        let mut res: Message<'_, {}, [_; {}], [_; {}], [_; {}]> = Message::unpack(&buf[..]);",
             out_raw, ipc_count, handle_copy_count, handle_move_count).unwrap();
    writeln!(s, "        res.error()?;").unwrap();

    match named_iterator(&cmd.ret, true).count() {
        0 => writeln!(s, "        Ok(())").unwrap(),
        1 => writeln!(s, "        Ok({})", format_ret(named_iterator(&cmd.ret, true).next().unwrap())?).unwrap(),
        _ => writeln!(s, "        Ok(({}))", named_iterator(&cmd.ret, true).map(format_ret).collect::<Result<Vec<String>, Error>>()?.join(", ")).unwrap()
    }
    writeln!(s, "    }}").unwrap();
    Ok(s)
}

/// Create a new type definition. For a [TypeDef::Struct], this will be a new
/// struct, For a [TypeDef::]
fn format_type(struct_name: &str, ty: &TypeDef) -> Result<String, Error> {
    let mut s = String::new();
    for line in ty.doc.lines() {
        writeln!(s, "/// {}", line).unwrap();
    }

    match &ty.ty {
        Type::Struct(struc) => {
            writeln!(s, "#[repr(C)]").unwrap();
            writeln!(s, "pub struct {} {{", struct_name).unwrap();
            for (doc, name, ty) in &struc.fields {
                // TODO: Support nested type
                for line in doc.lines() {
                    writeln!(s, "    /// {}", line).unwrap();
                }
                let tyname = match ty {
                    Type::Alias(alias) => get_type(false, alias)?,
                    _ => unimplemented!()
                };
                writeln!(s, "    {}: {},", name, tyname).unwrap();
            }
            writeln!(s, "}}").unwrap();
        },
        Type::Enum(enu) => {
            writeln!(s, "#[repr(u32)]").unwrap(); // TODO: Deduce from template
            writeln!(s, "pub enum {} {{", struct_name).unwrap();
            for (doc, name, num) in &enu.fields {
                for line in doc.lines() {
                    writeln!(s, "    /// {}", line).unwrap();
                }
                writeln!(s, "    {} = {},", name, num).unwrap();
            }
            writeln!(s, "}}").unwrap();
        },
        Type::Alias(alias) => {
            // TODO: Prevent alias of buffer/pid/handles
            writeln!(s, "pub type {} = {};", struct_name, get_type(false, &alias)?).unwrap();
        },
    }
    Ok(s)
}

/// A module hierarchy.
#[derive(Debug)]
struct Mod {
    /// Generated code for the types at the current level of the hierarchy.
    types: Vec<String>,
    /// Generated code for the ifaces at the current level of the hierarchy.
    ifaces: Vec<String>,
    /// Mapping from string to submodule hierarchy.
    mods: HashMap<String, Mod>,
}

/// Generate the module hierarchy. The depth should be set to 0 on the first call
/// and will be increased on each recursive call.
fn generate_mod(m: Mod, depth: usize, mod_name: &str, crate_name: &str) -> String {
    let mut s = String::new();

    let depthstr = "    ".repeat(depth);

    writeln!(s, "{}pub mod {} {{", depthstr, mod_name).unwrap();
    writeln!(s, "{}    //! Auto-generated documentation", depthstr).unwrap();
    writeln!(s, "{}    use crate as {};", depthstr, crate_name.replace("-", "_")).unwrap();
    writeln!(s).unwrap();

    if !m.ifaces.is_empty() {
        writeln!(s, "{}    use sunrise_libuser::types::ClientSession;", depthstr).unwrap();
        writeln!(s, "{}    use sunrise_libuser::error::Error;", depthstr).unwrap();
    }

    for (mod_name, modinfo) in m.mods {
        writeln!(s).unwrap();
        writeln!(s, "{}", generate_mod(modinfo, depth + 1, &mod_name, crate_name)).unwrap();
    }

    for ty in m.types {
        writeln!(s).unwrap();
        for line in ty.lines() {
            writeln!(s, "{}    {}", depthstr, line).unwrap();
        }
    }

    for iface in m.ifaces {
        writeln!(s).unwrap();
        for line in iface.lines() {
            writeln!(s, "{}    {}", depthstr, line).unwrap();
        }
    }

    writeln!(s, "{}}}", depthstr).unwrap();

    s
}

/// Generate a module containing all the functions in the given IPC file.
///
/// Strips the prefix from namespace path. The prefix should represents the
/// location of the module. For instance, if the module is being defined in
/// `libuser::ipc`, then prefix should contain `libuser::ipc`. If the file
/// contains any IPC outside the given prefix, an error will be raised.
///
/// The module name and crate name should be specified. This is used to allow
/// sunrise_libuser to `use` itself - since otherwise it will not be in the
/// namespace.
///
/// The generated string will contain a module hierarchy.
///
/// # Example
///
// TODO: Add an example of what generate_ipc generates.
pub fn generate_ipc(s: &str, prefix: String, mod_name: String, crate_name: String) -> String {
    // Read and parse the SwIPC file.
    let ctx = swipc_parser::parse(s);

    // Create the root module.
    let mut root_mod = Mod {
        types: Vec::new(),
        ifaces: Vec::new(),
        mods: HashMap::new()
    };

    for (typename, ty) in ctx.types {
        let path = typename.split("::");

        // Strip the prefix from the typename.
        let path = if !prefix.is_empty() {
            let mut it = prefix.split("::").zip(path);
            while let Some((item1, item2)) = it.next() {
                if item1 != item2 {
                    panic!("{} is outside of the prefix {}", typename, prefix);
                }
            }
            let (_, path): (Vec<_>, Vec<_>) = it.unzip();
            path
        } else {
            path.collect()
        };

        // Find (or create) the appropriate module in the mod hierarchy.
        let mut cur_mod = &mut root_mod;
        if !path.is_empty() {
            for elem in &path[..path.len() - 1] {
                cur_mod = cur_mod.mods.entry(elem.to_string()).or_insert(Mod {
                    types: Vec::new(),
                    ifaces: Vec::new(),
                    mods: HashMap::new()
                });
            }
        }

        let struct_name = typename.split("::").last().unwrap();

        // Generate the structure and add it to the appropriate module's type
        // list.
        match format_type(struct_name, &ty) {
            Ok(s) => cur_mod.types.push(s),
            Err(Error::UnsupportedStruct) => cur_mod.types.push(format!("// struct {}", struct_name))
        }
    }

    for (ifacename, interface) in ctx.interfaces {
        let path = ifacename.split("::");

        // Strip the prefix from the ifacename.
        let path = if !prefix.is_empty() {
            let mut it = prefix.split("::").zip(path);
            while let Some((item1, item2)) = it.next() {
                if item1 != item2 {
                    panic!("{} is outside of the prefix {}", ifacename, prefix);
                }
            }
            let (_, path): (Vec<_>, Vec<_>) = it.unzip();
            path
        } else {
            path.collect()
        };

        // Find (or create) the appropriate module in the mod hierarchy.
        let mut cur_mod = &mut root_mod;
        if !path.is_empty() {
            for elem in &path[..path.len() - 1] {
                cur_mod = cur_mod.mods.entry(elem.to_string()).or_insert(Mod {
                    types: Vec::new(),
                    ifaces: Vec::new(),
                    mods: HashMap::new()
                });
            }
        }

        let struct_name = ifacename.split("::").last().unwrap();

        let mut s = String::new();

        for line in interface.doc.lines() {
            writeln!(s, "/// {}", line).unwrap();
        }
        writeln!(s, "#[derive(Debug)]").unwrap();
        writeln!(s, "pub struct {}(ClientSession);", struct_name).unwrap();
        writeln!(s).unwrap();
        writeln!(s, "impl From<{}> for ClientSession {{", struct_name).unwrap();
        writeln!(s, "    fn from(sess: {}) -> ClientSession {{", struct_name).unwrap();
        writeln!(s, "        sess.0").unwrap();
        writeln!(s, "    }}").unwrap();
        writeln!(s, "}}").unwrap();
        writeln!(s).unwrap();
        writeln!(s, "impl From<ClientSession> for {} {{", struct_name).unwrap();
        writeln!(s, "    fn from(sess: ClientSession) -> {} {{", struct_name).unwrap();
        writeln!(s, "        {}(sess)", struct_name).unwrap();
        writeln!(s, "    }}").unwrap();
        writeln!(s, "}}").unwrap();

        if !interface.service_list.is_empty() {
            // For every service, we'll want to add a raw_new function.
            writeln!(s, "\nimpl {} {{", struct_name).unwrap();
            for (decorators, service) in &interface.service_list {
                let name = if interface.service_list.len() == 1 {
                    "".to_string()
                } else {
                    format!("_{}", service.replace(":", "_"))
                };

                writeln!(s, "    /// Creates a new [{}] by connecting to the `{}` service.", struct_name, service).unwrap();
                writeln!(s, "    pub fn raw_new{}() -> Result<{}, Error> {{", name, struct_name).unwrap();
                writeln!(s, "        use sunrise_libuser::syscalls;").unwrap();
                writeln!(s, "        use sunrise_libuser::error::KernelError;").unwrap();

                if decorators.iter().any(|v| matches!(let Decorator::ManagedPort = v)) {
                    // This service is a kernel-managed port.
                    writeln!(s, "        loop {{").unwrap();
                    let mut service_name = service.to_string();
                    service_name += &"\\0";
                    writeln!(s, r#"            let _ = match syscalls::connect_to_named_port("{}") {{"#, service_name).unwrap();
                    writeln!(s, "                Ok(s) => return Ok({}(s)),", struct_name).unwrap();
                    writeln!(s, "                Err(KernelError::NoSuchEntry) => syscalls::sleep_thread(0),").unwrap();
                    writeln!(s, "                Err(err) => Err(err)?").unwrap();
                    writeln!(s, "            }};").unwrap();
                    writeln!(s, "        }}").unwrap();
                } else {
                    // This service is a sm-managed port.
                    writeln!(s, "         use sunrise_libuser::error::SmError;").unwrap();
                    writeln!(s, "         ").unwrap();
                    writeln!(s, "         loop {{").unwrap();
                    writeln!(s, "              let svcname = unsafe {{").unwrap();
                    let mut service_name = service.to_string();
                    service_name += &"\\0".repeat(8 - service_name.len());
                    writeln!(s, r#"                  core::mem::transmute(*b"{}")"#, service_name).unwrap();
                    writeln!(s, "              }};").unwrap();
                    writeln!(s, "              let _ = match sunrise_libuser::sm::IUserInterface::raw_new()?.get_service(svcname) {{").unwrap();
                    writeln!(s, "                  Ok(s) => return Ok({}(s)),", struct_name).unwrap();
                    writeln!(s, "                  Err(Error::Sm(SmError::ServiceNotRegistered, ..)) => syscalls::sleep_thread(0),").unwrap();
                    writeln!(s, "                  Err(err) => return Err(err)").unwrap();
                    writeln!(s, "              }};").unwrap();
                    writeln!(s, "         }}").unwrap();
                }

                writeln!(s, "    }}").unwrap();
            }
            writeln!(s, "}}").unwrap();
        }

        writeln!(s, "impl {} {{", struct_name).unwrap();
        for cmd in interface.funcs {
            match format_cmd(&cmd) {
                Ok(out) => write!(s, "{}", out).unwrap(),
                Err(_) => writeln!(s, "    // pub fn {}(&mut self) -> Result<(), Error>", &cmd.name).unwrap()
            }
        }
        writeln!(s, "}}").unwrap();

        // Add the generated interface to the appropriate module's iface list.
        cur_mod.ifaces.push(s);
    }

    // Generate the final module hierarchy
    generate_mod(root_mod, 0, &mod_name, &crate_name)
}
