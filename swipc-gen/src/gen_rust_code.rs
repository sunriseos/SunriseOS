use lazy_static::lazy_static;

use std::fs;
use std::fmt::Write;
use std::path::Path;
use std::collections::HashMap;
use swipc_parser::{Alias, Func, KHandleType, TypeDef, Type};
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

#[derive(Debug)]
enum Error {
    UnsupportedStruct,
}

pub fn is_raw(val: &Alias) -> bool {
    match val {
        Alias::Bytes(_) | Alias::Align(_, _) | Alias::Other(_) => true,
        _ => false
    }
}

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
        (v, name.clone().unwrap_or(format!("unknown_{}", idx)))
    })
}

fn raw_iterator<'a, I>(it: I, is_output: bool) -> impl Iterator<Item = (&'a Alias, String)>
where
    I: IntoIterator<Item = &'a (Alias, Option<String>)>,
{
    named_iterator(it, is_output).filter(|(v, _name)| is_raw(v))
}


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

fn format_ret(ret: (&Alias, String)) -> Result<String, Error> {
    match ret.0 {
        Alias::Object(ty) => Ok(format!("{}::from(ClientSession(res.pop_handle_move()?))", ty)),
        Alias::KObject => Ok(format!("res.pop_handle_move()?")),
        Alias::KHandle(false, _) => Ok(format!("res.pop_handle_move()?")),
        Alias::KHandle(true, _) => Ok(format!("res.pop_handle_copy()?")),
        Alias::Pid => Ok(format!("res.pop_pid()?")),
        Alias::Bytes(..) |
        Alias::Align(..) |
        Alias::Other(..) => Ok(format!("res.raw().{}", ret.1)),
        _ => unreachable!()
    }
}

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

        Alias::Object(name) => Ok(format!("{}", name)),

        // Unsized bytes
        Alias::Bytes(0) => Ok("[u8]".to_string()),
        Alias::Bytes(len) => Ok(format!("[u8; {}]", len)),

        // Meh
        Alias::Align(_alignment, _underlying) => Err(Error::UnsupportedStruct),

        Alias::KObject => Ok("Handle".to_string()),
        Alias::KHandle(is_copy, ty) => {
            Ok(format!("{}{}", if *is_copy && !output { "&" } else { "" }, match ty {
                Some(KHandleType::ClientSession) => "kfs_libuser::types::ClientSession",
                Some(KHandleType::ServerSession) => "kfs_libuser::types::ServerSession",
                Some(KHandleType::ClientPort)    => "kfs_libuser::types::ClientPort",
                Some(KHandleType::ServerPort)    => "kfs_libuser::types::ServerPort",
                Some(KHandleType::SharedMemory)  => "kfs_libuser::types::SharedMemory",
                _                                => "kfs_libuser::types::Handle"
            }))
        },
        Alias::Pid => Ok("u64".to_string()),
        Alias::Other(ty) if ty == "unknown" => Err(Error::UnsupportedStruct),
        Alias::Other(ty) => Ok(ty.clone()),
    }
}

fn format_cmd(cmd: &Func) -> Result<String, Error> {
    let mut s = String::new();
    for line in cmd.doc.lines() {
        writeln!(s, "    /// {}", line).unwrap();
    }
    writeln!(s, "    pub fn {}(&mut self, {}) -> Result<{}, Error> {{", &cmd.name, format_args(&cmd.args, &cmd.ret)?, format_ret_ty(&cmd.ret)?).unwrap();
    writeln!(s, "        use kfs_libuser::ipc::Message;").unwrap();
    writeln!(s, "        let mut buf = [0; 0x100];").unwrap();
    writeln!(s, "").unwrap();
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
        Alias::KObject | Alias::KHandle(false, _) => true,
        _ => false
    }).count();
    let handle_copy_count = cmd.args.iter().filter(|(argty, _)| match argty {
        Alias::KHandle(true, _) => true,
        _ => false
    }).count();

    writeln!(s, "        let mut msg = Message::<{}, [_; {}], [_; {}], [_; {}]>::new_request(None, {});",
             in_raw, ipc_count, handle_move_count, handle_copy_count, cmd.num).unwrap();

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
        let argname = argname.clone().unwrap_or(format!("unknown_{}", idx));
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
            Alias::KHandle(false, Some(KHandleType::ClientSession))
          | Alias::KHandle(false, Some(KHandleType::ServerSession))
          | Alias::KHandle(false, Some(KHandleType::ClientPort))
          | Alias::KHandle(false, Some(KHandleType::ServerPort))
          | Alias::KHandle(false, Some(KHandleType::SharedMemory)) => writeln!(s, "        msg.push_handle_move({}.0);", argname).unwrap(),
            Alias::KHandle(true, Some(KHandleType::ClientSession))
          | Alias::KHandle(true, Some(KHandleType::ServerSession))
          | Alias::KHandle(true, Some(KHandleType::ClientPort))
          | Alias::KHandle(true, Some(KHandleType::ServerPort))
          | Alias::KHandle(true, Some(KHandleType::SharedMemory)) => writeln!(s, "        msg.push_handle_copy({}.0.as_ref());", argname).unwrap(),
            Alias::KObject | Alias::KHandle(false, _) => writeln!(s, "        msg.push_handle_move({});", argname).unwrap(),
            Alias::KHandle(true, _)                   => writeln!(s, "        msg.push_handle_copy({});", argname).unwrap(),
            Alias::Pid                                => writeln!(s, "        msg.send_pid(None);").unwrap(),
            _                                         => continue,
        }
    }

    writeln!(s, "        msg.pack(&mut buf[..]);").unwrap();
    writeln!(s, "        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;").unwrap();


    // TODO: Handle return C buffers.
    let ipc_count = 0;
    let handle_move_count = cmd.ret.iter().filter(|(argty, _)| match argty {
        Alias::KObject | Alias::KHandle(false, _) => true,
        _ => false
    }).count();
    let handle_copy_count = cmd.ret.iter().filter(|(argty, _)| match argty {
        Alias::KHandle(true, _) => true,
        _ => false
    }).count();

    writeln!(s, "").unwrap();
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
             out_raw, ipc_count, handle_move_count, handle_copy_count).unwrap();
    writeln!(s, "        res.error()?;").unwrap();

    match named_iterator(&cmd.ret, true).count() {
        0 => writeln!(s, "        Ok(())").unwrap(),
        1 => writeln!(s, "        Ok({})", format_ret(named_iterator(&cmd.ret, true).next().unwrap())?).unwrap(),
        _ => writeln!(s, "        Ok(({}))", named_iterator(&cmd.ret, true).map(format_ret).collect::<Result<Vec<String>, Error>>()?.join(", ")).unwrap()
    }
    writeln!(s, "    }}").unwrap();
    Ok(s)
}

fn format_struct(struct_name: &str, ty: &TypeDef) -> Result<String, Error> {
    let mut s = String::new();
    for line in ty.doc.lines() {
        writeln!(s, "/// {}", line).unwrap();
    }

    match &ty.ty {
        Type::Struct(struc) => {
            writeln!(s, "#[repr(C)]").unwrap();
            writeln!(s, "struct {} {{", struct_name).unwrap();
            for (doc, name, ty) in struc.fields.iter() {
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
            writeln!(s, "enum {} {{", struct_name).unwrap();
            for (doc, name, num) in enu.fields.iter() {
                for line in doc.lines() {
                    writeln!(s, "    /// {}", line).unwrap();
                }
                writeln!(s, "    {} = {},", name, num).unwrap();
            }
            writeln!(s, "}}").unwrap();
        },
        Type::Alias(alias) => {
            // TODO: Prevent alias of buffer/pid/handles
            writeln!(s, "type {} = {};", struct_name, get_type(false, &alias)?).unwrap();
        },
    }
    Ok(s)
}

#[derive(Debug)]
struct Mod {
    types: Vec<String>,
    ifaces: Vec<String>,
    mods: HashMap<String, Mod>,
}

fn generate_mod(m: Mod, depth: usize, mod_name: &str, crate_name: &str) -> String {
    let mut s = String::new();

    let depthstr = "    ".repeat(depth);

    writeln!(s, "{}mod {} {{", depthstr, mod_name).unwrap();
    writeln!(s, "{}    //! Auto-generated documentation", depthstr).unwrap();
    writeln!(s, "{}    use crate as {};", depthstr, crate_name.replace("-", "_")).unwrap();
    writeln!(s, "").unwrap();

    if m.ifaces.len() != 0 {
        writeln!(s, "{}    use kfs_libuser::types::ClientSession;", depthstr).unwrap();
        writeln!(s, "{}    use kfs_libuser::error::Error;", depthstr).unwrap();
    }

    for (mod_name, modinfo) in m.mods {
        writeln!(s, "").unwrap();
        writeln!(s, "{}", generate_mod(modinfo, depth + 1, &mod_name, crate_name)).unwrap();
    }

    for ty in m.types {
        writeln!(s, "").unwrap();
        for line in ty.lines() {
            writeln!(s, "{}    {}", depthstr, line).unwrap();
        }
    }

    for iface in m.ifaces {
        writeln!(s, "").unwrap();
        for line in iface.lines() {
            writeln!(s, "{}    {}", depthstr, line).unwrap();
        }
    }

    writeln!(s, "{}}}", depthstr).unwrap();

    s
}

pub fn generate_ipc(path: &Path, prefix: String, mod_name: String, crate_name: String) -> String {
    let ctx = swipc_parser::parse(&fs::read_to_string(path).unwrap());

    let mut root_mod = Mod {
        types: Vec::new(),
        ifaces: Vec::new(),
        mods: HashMap::new()
    };

    for (typename, ty) in ctx.types {
        let path = typename.split("::");
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

        match format_struct(struct_name, &ty) {
            Ok(s) => cur_mod.types.push(s),
            Err(Error::UnsupportedStruct) => cur_mod.types.push(format!("// struct {}", struct_name))
        }
    }

    for (ifacename, interface) in ctx.interfaces {
        let path = ifacename.split("::");
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

        writeln!(s, "#[derive(Debug)]").unwrap();
        writeln!(s, "pub struct {}(ClientSession);", struct_name).unwrap();
        writeln!(s, "").unwrap();
        writeln!(s, "impl From<{}> for ClientSession {{", struct_name).unwrap();
        writeln!(s, "    fn from(sess: {}) -> ClientSession {{", struct_name).unwrap();
        writeln!(s, "        sess.0").unwrap();
        writeln!(s, "    }}").unwrap();
        writeln!(s, "}}").unwrap();
        writeln!(s, "").unwrap();
        writeln!(s, "impl From<ClientSession> for {} {{", struct_name).unwrap();
        writeln!(s, "    fn from(sess: ClientSession) -> {} {{", struct_name).unwrap();
        writeln!(s, "        {}(sess)", struct_name).unwrap();
        writeln!(s, "    }}").unwrap();
        writeln!(s, "}}").unwrap();

        if !interface.service_list.is_empty() {
            writeln!(s, "\nimpl {} {{", struct_name).unwrap();
            for (decorators, service) in interface.service_list.iter() {
                let name = if interface.service_list.len() == 1 {
                    "".to_string()
                } else {
                    format!("_{}", service.replace(":", "_"))
                };
                writeln!(s, "    pub fn raw_new{}() -> Result<{}, Error> {{", name, struct_name).unwrap();
                writeln!(s, "         use kfs_libuser::syscalls;").unwrap();
                writeln!(s, "         use kfs_libuser::error::SmError;").unwrap();
                writeln!(s, "         ").unwrap();
                writeln!(s, "         loop {{").unwrap();
                writeln!(s, "              let svcname = unsafe {{").unwrap();
                let mut service_name = service.to_string();
                service_name += &"\\0".repeat(8 - service_name.len());
                writeln!(s, r#"                  core::mem::transmute(*b"{}")"#, service_name).unwrap();
                writeln!(s, "              }};").unwrap();
                writeln!(s, "              let _ = match kfs_libuser::sm::IUserInterface::raw_new()?.get_service(svcname) {{").unwrap();
                writeln!(s, "                  Ok(s) => return Ok({}(s)),", struct_name).unwrap();
                writeln!(s, "                  Err(Error::Sm(SmError::ServiceNotRegistered, ..)) => syscalls::sleep_thread(0),").unwrap();
                writeln!(s, "                  Err(err) => return Err(err)").unwrap();
                writeln!(s, "              }};").unwrap();
                writeln!(s, "         }}").unwrap();
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

        cur_mod.ifaces.push(s);
    }

    generate_mod(root_mod, 0, &mod_name, &crate_name)
}
