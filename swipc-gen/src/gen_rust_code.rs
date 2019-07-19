//! Code generation implementation
//!
//! Entrypoint is [generate_ipc](crate::gen_rust_code::generate_ipc).

use lazy_static::lazy_static;

use std::fmt::Write;
use std::collections::HashMap;
use swipc_parser::{Alias, Func, HandleType, TypeDef, Type, Decorator, Interface};
use bit_field::BitField;

/// Rename field names that would conflict with rust keywords.
fn remap_keywords(s: &str) -> &'_ str {
    match s {
        "type" => "ty",
        s => s
    }
}

lazy_static! {
    /// SwIPC builtin type. Associates a SwIPC builtin name with a size/alignment
    /// and a rust type name.
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
        (v, name.as_ref().map(|v| remap_keywords(v).to_string()).unwrap_or_else(|| format!("unknown_{}", idx)))
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
fn format_args(args: &[(Alias, Option<String>)], ret: &[(Alias, Option<String>)], server: bool) -> Result<String, Error> {
    let mut arg_list = Vec::new();
    for (idx, (ty, name)) in args.iter().chain(ret.iter().filter(|(ty, _)| {
        match ty { Alias::Array(..) | Alias::Buffer(..) => true, _ => false }
    })).enumerate()
    {
        let mut s = String::new();
        if !server {
            if let Alias::Pid = ty {
                continue;
            }
        }
        match name.as_ref().map(|v| &**v) {
            // TODO: More thorough keyword sanitizer in swipc generator.
            // BODY: The SwIPC generator does little to no sanitizing of argument
            // BODY: names that may be keywords in rust. We should have a list of
            // BODY: keywords and a central function to fix them up.
            // Rename type to ty since type is a keyword in rust.
            Some(name) => s += remap_keywords(name),
            None => s += &format!("unknown_{}", idx)
        }
        s += ": ";
        s += &get_type(idx >= args.len(), ty, server)?;
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
fn format_ret_ty(ret: &[(Alias, Option<String>)], server: bool) -> Result<String, Error> {
    let mut v = Vec::new();

    for (ty, _name) in named_iterator(ret, true) {
        v.push(get_type(true, ty, server)?);
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
fn get_handle_type(ty: &Option<HandleType>) -> Option<&'static str> {
    match ty {
        Some(HandleType::ClientSession) => Some("self::sunrise_libuser::types::ClientSession"),
        Some(HandleType::ServerSession) => Some("self::sunrise_libuser::types::ServerSession"),
        Some(HandleType::ClientPort)    => Some("self::sunrise_libuser::types::ClientPort"),
        Some(HandleType::ServerPort)    => Some("self::sunrise_libuser::types::ServerPort"),
        Some(HandleType::SharedMemory)  => Some("self::sunrise_libuser::types::SharedMemory"),
        Some(HandleType::Process)       => Some("self::sunrise_libuser::types::Process"),
        Some(HandleType::Thread)        => Some("self::sunrise_libuser::types::Thread"),
        _                               => None
    }
}

/// Generate code to recover a single return value from an output Message.
fn format_ret(ret: (&Alias, String)) -> Result<String, Error> {
    match ret.0 {
        Alias::Object(ty) => Ok(format!("{}Proxy::from(ClientSession(res__.pop_handle_move()?))", ty)),
        Alias::Handle(is_copy, ty) => if let Some(s) = get_handle_type(ty) {
            Ok(format!("{}(res__.pop_handle_{}()?)", s, if *is_copy { "copy" } else { "move" }))
        } else {
            Ok(format!("res__.pop_handle_{}()?", if *is_copy { "copy" } else { "move" }))
        },
        Alias::Pid => Ok("res__.pop_pid()?".to_string()),
        Alias::Bytes(..) |
        Alias::Align(..) |
        Alias::Other(..) => Ok(format!("res__.raw().{}", ret.1)),
        _ => unreachable!()
    }
}

/// Get the Rust type of an [Alias]. If output is true, then the type should be
/// suitable for a return type (or an output IPC buffer argument). If output is
/// false, then the type should be suitable for an input argument.
fn get_type(output: bool, ty: &Alias, is_server: bool) -> Result<String, Error> {
    let is_mut = if output { "mut " } else { "" };
    match ty {
        // actually a special kind of buffer
        Alias::Array(underlying, _) => Ok(format!("&{}[{}]", is_mut, get_type(output, underlying, is_server)?)),

        // Blow up if we don't know the size or type
        Alias::Buffer(box Alias::Other(name), _, None) if name == "unknown" => Err(Error::UnsupportedStruct),
        // Treat unknown but sized types as an opaque byte array
        Alias::Buffer(box Alias::Other(name), _, Some(size)) if name == "unknown" => Ok(format!("&{}[u8; {:#x}]", is_mut, size)),
        // 0-sized buffer means it takes an array
        Alias::Buffer(inner @ box Alias::Other(_), _, None) => Ok(format!("&{}[{}]", is_mut, get_type(output, inner, is_server)?)),
        // Typed buffers are just references to the underlying raw object
        Alias::Buffer(inner @ box Alias::Bytes(_), _, _) |
        Alias::Buffer(inner @ box Alias::Other(_), _, _) => Ok(format!("&{}{}", is_mut, get_type(output, inner, is_server)?)),
        // Panic if we get a buffer with an unsupported underlying type.
        Alias::Buffer(underlying, _, _) => panic!("Buffer with underlying type {:?}", underlying),

        Alias::Object(name) => {
            if output {
                Ok(name.clone() + "Proxy")
            } else {
                Ok(format!("impl {}", name))
            }
        },

        // Unsized bytes
        Alias::Bytes(Some(0)) | Alias::Bytes(None) => Ok("[u8]".to_string()),
        Alias::Bytes(Some(len)) => Ok(format!("[u8; {}]", len)),

        // Deprecated in newer version of SwIPC anyways.
        Alias::Align(_alignment, _underlying) => Err(Error::UnsupportedStruct),

        Alias::Handle(is_copy, ty) => if let Some(s) = get_handle_type(ty) {
            Ok(format!("{}{}", if *is_copy && !is_server && !output { "&" } else { "" }, s))
        } else if *is_copy && is_server && output {
            Ok("self::sunrise_libuser::types::HandleRef<'static>".to_string())
        } else {
            Ok(format!("self::sunrise_libuser::types::{}", if *is_copy && !is_server && !output { "HandleRef" } else { "Handle" }))
        },
        Alias::Pid => Ok("self::sunrise_libuser::types::Pid".to_string()),
        Alias::Other(ty) if ty == "unknown" => Err(Error::UnsupportedStruct),
        Alias::Other(ty) => Ok(ty.clone()),
    }
}

/// Generates the InRaw structure from the argument list of a function. This
/// structure corresponds to the Raw Data that will be sent in the request of an
/// IPC message.
fn gen_in_raw(s: &mut String, cmd: &Func) -> Result<&'static str, Error>  {
    if cmd.args.iter().any(|(argty, _)| is_raw(argty)) {
        writeln!(s, "        #[repr(C)]").unwrap();
        writeln!(s, "        #[derive(Clone, Copy)]").unwrap();
        writeln!(s, "        #[allow(clippy::missing_docs_in_private_items)]").unwrap();
        writeln!(s, "        struct InRaw {{").unwrap();
        for (argty, argname) in raw_iterator(&cmd.args, false) {
            writeln!(s, "            {}: {},", argname, get_type(false, argty, false)?).unwrap();
        }
        writeln!(s, "        }}").unwrap();
        Ok("InRaw")
    } else {
        Ok("()")
    }
}

/// Generates the OutRaw structure from the return param list of a function.
/// This structure corresponds to the Raw Data that will be sent in the response
/// of an IPC message.
fn gen_out_raw(s: &mut String, cmd: &Func) -> Result<&'static str, Error> {
    if cmd.ret.iter().any(|(argty, _)| is_raw(argty)) {
        writeln!(s, "        #[repr(C)]").unwrap();
        writeln!(s, "        #[derive(Clone, Copy)]").unwrap();
        writeln!(s, "        #[allow(clippy::missing_docs_in_private_items)]").unwrap();
        writeln!(s, "        struct OutRaw {{").unwrap();
        for (argty, argname) in raw_iterator(&cmd.ret, true) {
            writeln!(s, "            {}: {},", argname, get_type(true, argty, false)?).unwrap();
        }
        writeln!(s, "        }}").unwrap();
        Ok("OutRaw")
    } else {
        Ok("()")
    }
}

/// Generate code for a single function.
fn format_cmd(cmd: &Func) -> Result<String, Error> {
    let mut s = String::new();
    for line in cmd.doc.lines() {
        writeln!(s, "    /// {}", line).unwrap();
    }
    writeln!(s, "    pub fn {}(&self, {}) -> Result<{}, Error> {{", &cmd.name, format_args(&cmd.args, &cmd.ret, false)?, format_ret_ty(&cmd.ret, false)?).unwrap();
    writeln!(s, "        use self::sunrise_libuser::ipc::Message;").unwrap();
    writeln!(s, "        let mut buf__ = [0; 0x100];").unwrap();
    writeln!(s).unwrap();
    let in_raw = gen_in_raw(&mut s, cmd)?;

    let ipc_count = cmd.args.iter().chain(&cmd.ret).filter(|(argty, _)| match argty {
        Alias::Array(..) | Alias::Buffer(..) => true,
        _ => false
    }).count();
    let handle_move_count = cmd.args.iter().filter(|(argty, _)| match argty {
        Alias::Handle(false, _) | Alias::Object(_) => true,
        _ => false
    }).count();
    let handle_copy_count = cmd.args.iter().filter(|(argty, _)| match argty {
        Alias::Handle(true, _) => true,
        _ => false
    }).count();

    writeln!(s, "        let mut msg__ = Message::<{}, [_; {}], [_; {}], [_; {}]>::new_request(None, {});",
             in_raw, ipc_count, handle_copy_count, handle_move_count, cmd.num).unwrap();

    if cmd.args.iter().any(|(argty, _)| is_raw(argty)) {
        writeln!(s, "        msg__.push_raw(InRaw {{").unwrap();
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
            Alias::Array(_alias, ty)                    => {
                match (ty.get_bits(0..2), ty.get_bits(2..4), ty.get_bit(5)) {
                    // A Buffer
                    (1, 1, false) => writeln!(s, "        msg__.push_out_buffer({});", argname).unwrap(),
                    // B Buffer
                    (2, 1, false) => writeln!(s, "        msg__.push_in_buffer({});", argname).unwrap(),
                    // X Buffer
                    (1, 2, false) => writeln!(s, "        msg__.push_out_pointer({});", argname).unwrap(),
                    // C Buffer
                    (2, 2, false) => writeln!(s, "        msg__.push_in_pointer({}, {});", argname, !ty.get_bit(4)).unwrap(),
                    // Smart A+X
                    (1, 0, true) => return Err(Error::UnsupportedStruct),
                    // Smart B+C
                    (2, 0, true) => return Err(Error::UnsupportedStruct),
                    _ => panic!("Illegal buffer type: {}", ty)
                }
            },
            Alias::Buffer(_alias, ty, _)               => {
                match (ty.get_bits(0..2), ty.get_bits(2..4), ty.get_bit(5)) {
                    // A Buffer
                    (1, 1, false) => writeln!(s, "        msg__.push_out_buffer({});", argname).unwrap(),
                    // B Buffer
                    (2, 1, false) => writeln!(s, "        msg__.push_in_buffer({});", argname).unwrap(),
                    // X Buffer
                    (1, 2, false) => writeln!(s, "        msg__.push_out_pointer({});", argname).unwrap(),
                    // C Buffer
                    (2, 2, false) => writeln!(s, "        msg__.push_in_pointer({}, {});", argname, !ty.get_bit(4)).unwrap(),
                    // Smart A+X
                    (1, 0, true) => return Err(Error::UnsupportedStruct),
                    // Smart B+C
                    (2, 0, true) => return Err(Error::UnsupportedStruct),
                    _ => panic!("Illegal buffer type: {}", ty)
                }
            },
            Alias::Object(_)                          => writeln!(s, "        msg__.push_handle_move({}.into());", argname).unwrap(),
            Alias::Handle(false, ty) if get_handle_type(ty).is_some() =>
                writeln!(s, "        msg__.push_handle_move({}.0);", argname).unwrap(),
            Alias::Handle(false, _) =>
                writeln!(s, "        msg__.push_handle_move({});", argname).unwrap(),
            Alias::Handle(true, ty) if get_handle_type(ty).is_some() =>
                writeln!(s, "        msg__.push_handle_copy({}.0.as_ref());", argname).unwrap(),
            Alias::Handle(true, _) =>
                writeln!(s, "        msg__.push_handle_copy({});", argname).unwrap(),
            Alias::Pid                                => writeln!(s, "        msg__.send_pid(None);").unwrap(),
            _                                         => continue,
        }
    }

    writeln!(s, "        msg__.pack(&mut buf__[..]);").unwrap();
    writeln!(s, "        self.0.send_sync_request_with_user_buffer(&mut buf__[..])?;").unwrap();


    // TODO: Handle return C buffers.
    let ipc_count = 0;
    let handle_move_count = cmd.ret.iter().filter(|(argty, _)| match argty {
        Alias::Handle(false, _) | Alias::Object(_) => true,
        _ => false
    }).count();
    let handle_copy_count = cmd.ret.iter().filter(|(argty, _)| match argty {
        Alias::Handle(true, _) => true,
        _ => false
    }).count();

    writeln!(s).unwrap();
    let out_raw = gen_out_raw(&mut s, cmd)?;

    writeln!(s, "        let mut res__: Message<'_, {}, [_; {}], [_; {}], [_; {}]> = Message::unpack(&buf__[..]);",
             out_raw, ipc_count, handle_copy_count, handle_move_count).unwrap();
    writeln!(s, "        res__.error()?;").unwrap();

    match named_iterator(&cmd.ret, true).count() {
        0 => writeln!(s, "        Ok(())").unwrap(),
        1 => writeln!(s, "        Ok({})", format_ret(named_iterator(&cmd.ret, true).next().unwrap())?).unwrap(),
        _ => writeln!(s, "        Ok(({}))", named_iterator(&cmd.ret, true).map(format_ret).collect::<Result<Vec<String>, Error>>()?.join(", ")).unwrap()
    }
    writeln!(s, "    }}").unwrap();
    Ok(s)
}

/// Create a new type definition. For a `TypeDef::Struct`, this will be a new
/// struct, For a `TypeDef::Enum`, it will be a new enum, and for a
/// `TypeDef::Alias`, it will be a rust `type` alias.
fn format_type(struct_name: &str, ty: &TypeDef) -> Result<String, Error> {
    let mut s = String::new();

    if let Type::Enum(_) = &ty.ty {
        // Do nothing here
    } else {
        for line in ty.doc.lines() {
            writeln!(s, "/// {}", line).unwrap();
        }
    }

    match &ty.ty {
        Type::Struct(struc) => {
            writeln!(s, "#[repr(C)]").unwrap();
            writeln!(s, "#[derive(Clone, Copy, Debug)]").unwrap();
            writeln!(s, "pub struct {} {{", struct_name).unwrap();
            for (doc, name, ty) in &struc.fields {
                // TODO: Support nested type
                for line in doc.lines() {
                    writeln!(s, "    /// {}", line).unwrap();
                }
                let tyname = match ty {
                    Type::Alias(alias) => get_type(false, alias, false)?,
                    _ => unimplemented!()
                };
                writeln!(s, "    pub {}: {},", remap_keywords(name), tyname).unwrap();
            }
            writeln!(s, "}}").unwrap();
        },
        Type::Enum(enu) => {
            writeln!(s, "enum_with_val! {{").unwrap();
            for line in ty.doc.lines() {
                writeln!(s, "    /// {}", line).unwrap();
            }
            writeln!(s, "    #[derive(PartialEq, Eq, Clone, Copy)]").unwrap();
            writeln!(s, "    pub struct {}({}) {{", struct_name, enu.tyname).unwrap();
            for (doc, name, num) in &enu.fields {
                for line in doc.lines() {
                    writeln!(s, "        /// {}", line).unwrap();
                }
                writeln!(s, "        {} = {},", remap_keywords(name), num).unwrap();
            }
            writeln!(s, "    }}").unwrap();
            writeln!(s, "}}").unwrap();
        },
        Type::Alias(alias) => {
            // TODO: Prevent alias of buffer/pid/handles
            writeln!(s, "pub type {} = {};", struct_name, get_type(false, &alias, false)?).unwrap();
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
fn generate_mod(m: Mod, depth: usize, mod_name: &str, crate_name: &str, is_root_mod: bool) -> String {
    let mut s = String::new();

    let depthstr = "    ".repeat(depth);

    if !is_root_mod {
        writeln!(s, "{}pub mod {} {{", depthstr, mod_name).unwrap();
    }
    writeln!(s, "{}    //! Auto-generated documentation", depthstr).unwrap();
    writeln!(s, "{}    use crate as {};", depthstr, crate_name.replace("-", "_")).unwrap();
    writeln!(s).unwrap();

    if !m.ifaces.is_empty() {
        writeln!(s, "{}    use self::sunrise_libuser::types::ClientSession;", depthstr).unwrap();
        writeln!(s, "{}    use self::sunrise_libuser::error::Error;", depthstr).unwrap();
    }

    for (mod_name, modinfo) in m.mods {
        writeln!(s).unwrap();
        writeln!(s, "{}", generate_mod(modinfo, depth + 1, &mod_name, crate_name, false)).unwrap();
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

    if !is_root_mod {
        writeln!(s, "{}}}", depthstr).unwrap();
    }
    s
}

/// Parse an incoming request, call the appropriate function from the trait
/// we're currently generating (see [generate_trait()]), and fill the byte buffer with
/// the response data.
fn gen_call(cmd: &Func) -> Result<String, Error> {
    let mut s = String::new();
    let in_raw = gen_in_raw(&mut s, cmd)?;
    let ipc_count = cmd.args.iter().chain(&cmd.ret).filter(|(argty, _)| match argty {
        Alias::Array(..) | Alias::Buffer(..) => true,
        _ => false
    }).count();
    let handle_move_count = cmd.args.iter().filter(|(argty, _)| match argty {
        Alias::Handle(false, _) | Alias::Object(_) => true,
        _ => false
    }).count();
    let handle_copy_count = cmd.args.iter().filter(|(argty, _)| match argty {
        Alias::Handle(true, _) => true,
        _ => false
    }).count();

    writeln!(s, "                let mut msg__ = Message::<{}, [_; {}], [_; {}], [_; {}]>::unpack(buf);",
         in_raw, ipc_count, handle_copy_count, handle_move_count).unwrap();

    let mut args = String::new();
    for (item, name) in named_iterator(&cmd.args, false)
        .chain(named_iterator(&cmd.ret, false).filter(|(ty, _)|
            match ty { Alias::Array(..) | Alias::Buffer(..) => true, _ => false }))
    {
        match item {
            Alias::Array(underlying_ty, bufty) | Alias::Buffer(underlying_ty, bufty, _) => {
                let (ismut,direction, ty) = match (bufty.get_bits(0..2), bufty.get_bits(2..4)) {
                    (0b01, 0b01) => ("", "in", "buffer"),
                    (0b01, 0b10) => ("", "in", "pointer"),
                    (0b10, 0b01) => ("mut", "out", "buffer"),
                    (0b10, 0b10) => ("mut", "out", "pointer"),
                    _ => panic!("Invalid bufty")
                };
                let realty = get_type(false, underlying_ty, false)?;
                if let Alias::Array(..) = item {
                    // TODO: Make pop_out_buffer and co safe to call.
                    // BODY: Currently, pop_out_buffer (and other functions of
                    // BODY: that family) are unsafe to call as they basically
                    // BODY: allow transmuting variables. We should use a crate
                    // BODY: like `plain` to ensure that said functions are only
                    // BODY: callable when it is safe.
                    args += &format!("unsafe {{ &{} *msg__.pop_{}_{}::<[{}]>().unwrap() }}, ", ismut, direction, ty, realty);
                } else {
                    args += &format!("unsafe {{ &{} *msg__.pop_{}_{}::<{}>().unwrap() }}, ", ismut, direction, ty, realty);
                }
            },
            Alias::Object(ty) => {
                args += &format!("{}Proxy(self::sunrise_libuser::types::ClientSession(msg__.pop_handle_move().unwrap())), ", ty);
            },
            Alias::Handle(is_copy, ty) => {
                let handle = if *is_copy {
                    "msg__.pop_handle_copy().unwrap()"
                } else {
                    "msg__.pop_handle_move().unwrap()"
                };
                let to_add = match get_handle_type(ty) {
                    Some(ty) => format!("{}({}), ", ty, handle),
                    _ => format!("{}, ", handle)
                };

                args += &to_add;
            },
            Alias::Pid => {
                args += "msg__.pop_pid().unwrap(), ";
            },
            Alias::Align(..) | Alias::Bytes(..) | Alias::Other(..) => {
                args += &format!("msg__.raw().{}, ", name);
            },
        }
    }
    writeln!(s, "                let ret__ = self.{}(manager, {});", &cmd.name, args).unwrap();

    let out_raw = gen_out_raw(&mut s, cmd)?;
    let handle_move_count = cmd.ret.iter().filter(|(argty, _)| match argty {
        Alias::Handle(false, _) | Alias::Object(_) => true,
        _ => false
    }).count();
    let handle_copy_count = cmd.ret.iter().filter(|(argty, _)| match argty {
        Alias::Handle(true, _) => true,
        _ => false
    }).count();

    writeln!(s, "                let mut msg__ = Message::<{}, [_; 0], [_; {}], [_; {}]>::new_response(None);",
         out_raw, handle_copy_count, handle_move_count).unwrap();

    writeln!(s, "                match  ret__ {{").unwrap();
    writeln!(s, "                    Ok(ret) => {{").unwrap();

    let retcount = named_iterator(&cmd.ret, true).count();
    for (idx, (item, _)) in named_iterator(&cmd.ret, true).enumerate().filter(|(_, (ty, _))| !is_raw(ty))
    {
        let ret = if retcount == 1 {
            "ret".to_string()
        } else {
            format!("ret.{}", idx)
        };
        match item {
            Alias::Object(_) => {
                writeln!(s, "msg__.push_handle_move({}.0.into_handle());", ret).unwrap();
            },
            Alias::Handle(is_copy, ty) => {
                let (is_ref, handle) = if *is_copy {
                    (".as_ref()", "copy")
                } else {
                    ("", "move")
                };
                match (get_handle_type(ty), ty) {
                    (_, Some(HandleType::ClientSession)) => writeln!(s, "msg__.push_handle_{}(({}).into_handle(){});", handle, ret, is_ref).unwrap(),
                    (Some(_), _) => writeln!(s, "msg__.push_handle_{}(({}).0{});", handle, ret, is_ref).unwrap(),
                    _ => writeln!(s, "msg__.push_handle_{}({});", handle, ret).unwrap(),
                };
            },
            Alias::Pid => {
                writeln!(s, "msg__.push_pid().unwrap();").unwrap();
            },
            _ => unreachable!()
        }
    }

    if raw_iterator(&cmd.ret, true).count() > 0 {
        if named_iterator(&cmd.ret, true).count() == 1 {
            let (_, name) = raw_iterator(&cmd.ret, true).next().unwrap();
            writeln!(s, "msg__.push_raw({} {{ {}: ret }});", out_raw, name).unwrap();
        } else {
            writeln!(s, "msg__.push_raw({} {{", out_raw).unwrap();
            for (idx, (_, name)) in named_iterator(&cmd.ret, true).enumerate().filter(|(_, (ty, _))| is_raw(ty))
            {
                writeln!(s, "{}: ret.{},", name, idx).unwrap();
            }
            writeln!(s, "}});").unwrap();
        }
    }

    writeln!(s, "                    }},").unwrap();
    writeln!(s, "                    Err(err) => {{ msg__.set_error(err.as_code()); }}").unwrap();
    writeln!(s, "                }}").unwrap();
    writeln!(s).unwrap();
    writeln!(s, "                msg__.pack(buf);").unwrap();
    writeln!(s, "                Ok(())").unwrap();
    Ok(s)
}

/// Generate a trait representing an IPC interface. Implementors of this trait
/// may then create IPC Server objects through libuser's SessionWrapper and
/// PortHandler.
pub fn generate_trait(ifacename: &str, interface: &Interface) -> String {
    let mut s = String::new();

    let trait_name = ifacename.split("::").last().unwrap().to_string();

    for line in interface.doc.lines() {
        writeln!(s, "/// {}", line).unwrap();
    }
    writeln!(s, "pub trait {} {{", trait_name).unwrap();
    for cmd in &interface.funcs {
        match format_args(&cmd.args, &cmd.ret, true).and_then(|v| format_ret_ty(&cmd.ret, true).map(|u| (v, u))) {
            Ok((args, ret)) => {
                for line in cmd.doc.lines() {
                    writeln!(s, "/// {}", line).unwrap();
                }
                writeln!(s, "    fn {}(&mut self, manager: &self::sunrise_libuser::ipc::server::WaitableManager, {}) -> Result<{}, Error>;", &cmd.name, args, ret).unwrap();
            },
            Err(_) => writeln!(s, "    // fn {}(&mut self) -> Result<(), Error>;", &cmd.name).unwrap()
        }
    }

    writeln!(s, "    /// Handle an incoming IPC request.").unwrap();
    writeln!(s, "    fn dispatch(&mut self, manager: &self::sunrise_libuser::ipc::server::WaitableManager, cmdid: u32, buf: &mut [u8]) -> Result<(), Error> {{").unwrap();
    writeln!(s, "        use self::sunrise_libuser::ipc::Message;").unwrap();
    writeln!(s, "        match cmdid {{").unwrap();
    for func in &interface.funcs {
        if let Ok(val) = gen_call(&func) {
            writeln!(s, "            {} => {{", func.num).unwrap();
            writeln!(s, "{}", val).unwrap();
            writeln!(s, "            }},").unwrap();
        } else {
            writeln!(s, "            // Unsupported: {}", func.num).unwrap();
        }
    }
    writeln!(s, "            _ => {{").unwrap();
    writeln!(s, "                let mut msg__ = Message::<(), [_; 0], [_; 0], [_; 0]>::new_response(None);").unwrap();
    writeln!(s, "                msg__.set_error(sunrise_libkern::error::KernelError::PortRemoteDead.make_ret() as u32);").unwrap();
    writeln!(s, "                msg__.pack(buf);").unwrap();
    writeln!(s, "                Ok(())").unwrap();
    writeln!(s, "            }}").unwrap();
    writeln!(s, "        }}").unwrap();
    writeln!(s, "    }}").unwrap();

    writeln!(s, "}}").unwrap();

    s
}

/// Generate a "proxy" interface (nomenclature shamelessly stolen from binder).
/// A "proxy" is a client interface to a remote IPC object.
pub fn generate_proxy(ifacename: &str, interface: &Interface) -> String {
    let struct_name = ifacename.split("::").last().unwrap().to_string() + "Proxy";

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
            writeln!(s, "        use self::sunrise_libuser::syscalls;").unwrap();
            writeln!(s, "        use self::sunrise_libuser::error::KernelError;").unwrap();

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
                writeln!(s, "         use self::sunrise_libuser::error::SmError;").unwrap();
                writeln!(s, "         ").unwrap();
                writeln!(s, "         loop {{").unwrap();
                writeln!(s, "              let svcname = unsafe {{").unwrap();
                let mut service_name = service.to_string();
                service_name += &"\\0".repeat(8 - service_name.len());
                writeln!(s, r#"                  core::mem::transmute(*b"{}")"#, service_name).unwrap();
                writeln!(s, "              }};").unwrap();
                writeln!(s, "              let _ = match self::sunrise_libuser::sm::IUserInterfaceProxy::raw_new()?.get_service(svcname) {{").unwrap();
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
    for cmd in &interface.funcs {
        match format_cmd(&cmd) {
            Ok(out) => write!(s, "{}", out).unwrap(),
            Err(_) => writeln!(s, "    // pub fn {}(&self) -> Result<(), Error>", &cmd.name).unwrap()
        }
    }
    writeln!(s, "}}").unwrap();

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
pub fn generate_ipc(s: &str, prefix: String, mod_name: String, crate_name: String, is_root_mod: bool) -> String {
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

        // Add the generated interface to the appropriate module's iface list.
        cur_mod.ifaces.push(generate_proxy(&ifacename, &interface));
        cur_mod.ifaces.push(generate_trait(&ifacename, &interface));
    }

    // Generate the final module hierarchy
    generate_mod(root_mod, 0, &mod_name, &crate_name, is_root_mod)
}
