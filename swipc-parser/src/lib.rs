//! Efficient parser for the SwIPC files
//!
//! SwIPC is your one-stop-shop for Nintendo Switch IPC definitions. The format
//! is documented on [the SwIPC repo](https://github.com/reswitched/SwIPC). This
//! crate can parse the SwIPC auto.id file almost instantaneously, removing the
//! need for the old python parser's need for caches.
//!
//! The main entry-point for this crate is the [parse] function, which takes a
//! string containing the content you want to parse, and returns a [Ctx] struct
//! containing all the definitions parsed. If the file didn't parse, we panic.
//!
//! # Example
//!
//! ```
//! # let vi = "# Entry point interface.
//! # interface libuser::vi::ViInterface is vi {
//! #     # Gets the screen resolution.
//! #     [1] get_resolution() -> (u32 width, u32 height);
//! # }";
//! let ctx = parse(vi);
//! let vi = ctx.interfaces["libuser::vi::ViInterface"];
//! for func in vi.funcs {
//!     println!("[{}] {}: {}", func.num, func.name, func.doc);
//! }
//! ```

// rustc warnings
#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(intra_doc_link_resolution_failure)]

// TODO: Bring the SwIPC parser in-line with new upstream format.
// BODY: Unknown can now carry a size (which behaves like bytes). Unsized unknown
// BODY: should be treated as an unsupported struct.
// BODY:
// BODY: Struct should now carry their size (and can optionally be validated).
// BODY:
// BODY: Buffer size is now optional, and defaults to variable/client-sized. 

#[macro_use]
extern crate pest_derive;

use pest::Parser;
use pest::iterators::{Pairs, Pair};
use std::collections::HashMap;

mod pest_parser {
    #![allow(missing_docs)]
    #![allow(clippy::missing_docs_in_private_items)]

    #[derive(Parser)]
    #[grammar = "grammar.pest"]
    pub struct SwipcParser;
}

use pest_parser::*;

/// A new type definition.
///
/// [SwIPC doc](https://github.com/reswitched/SwIPC#typedefs).
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct TypeDef {
    pub doc: String,
    pub name: String,
    pub ty: Type
}

/// Struct definition.
///
/// Can optionally be decorated with a size.
///
/// The fields tuple contains (documentation, name, type).
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct Struct {
    pub size: Option<u64>,
    pub fields: Vec<(String, String, Type)>
}

/// Enum definition.
///
/// The tyname represents the size of the enum. Can be u8, u16, u32 or u64.
///
/// The fields tuple contains (documentation, name, number).
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct Enum {
    pub tyname: String,
    pub fields: Vec<(String, String, u64)>
}

/// Type of a Handle. Represents all the kernel handle types on the Horizon/NX
/// kernel.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
pub enum HandleType {
    Process, Thread, Debug, CodeMemory, TransferMemory, SharedMemory,
    ServerPort, ClientPort, ServerSession, ClientSession,
    ServerLightSession, ClientLightSession, ReadableEvent, WritableEvent,
    IrqEvent, DeviceAddressSpace
}

/// A type alias.
///
/// To simplify the grammar a bit, it also contains the special types.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum Alias {
    /// Buffer Array. Equivalent to buffer<data_type, transfer_type, variable>
    Array(Box<Alias>, u64),
    /// An IPC Buffer transfering untyped data.
    /// First argument represents underlying datatype, second argument represents
    /// the IPC buffer kind [as described on switchbrew], and the third
    /// argument is the size.
    ///
    /// [as described on switchbrew]: https://switchbrew.org/w/index.php?title=IPC_Marshalling#Official_marshalling_code
    Buffer(Box<Alias>, u64, u64),
    /// An IPC Object implementing the given interface.
    Object(String),
    /// A byte blob of the given size.
    Bytes(u64),
    /// Forces the alignment to the given size for the given underlying type.
    Align(u64, Box<Alias>),
    /// A Kernel Handle of the given type. If the first argument is true, the
    /// handle is a copy Handle, otherwise it's a move a handle.
    Handle(bool, Option<HandleType>),
    /// A Pid.
    Pid,
    /// Either a builtin or another structure.
    Other(String)
}

/// A new type definition.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum Type {
    /// Creates a new structure
    Struct(Struct),
    /// Creates a new enum
    Enum(Enum),
    /// Creates a new type alias
    Alias(Alias),
}

/// Represents a decorator.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum Decorator {
    /// Can be attached to a function to specify that its types are unknown.
    Undocumented,
    /// Can be attached to a function to specify that the function was added
    /// or removed in a specific version.
    ///
    /// First argument specifies which version the function was added in - it
    /// defaults to 1.0.0. The second argument specifies when the function was
    /// removed, or None if it's still around.
    Version(String, Option<String>),
    /// Can be attached to a service to tag it as a kernel-managed port.
    ManagedPort,
    /// A decorator not known by this parser.
    Unknown(String, String),
}

/// A function on an interface.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct Func {
    pub doc: String,
    pub decorators: Vec<Decorator>,
    pub num: u64,
    pub name: String,
    pub args: Vec<(Alias, Option<String>)>,
    pub ret: Vec<(Alias, Option<String>)>
}

/// An interface definition.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct Interface {
    pub doc: String,
    pub name: String,
    pub service_list: Vec<(Vec<Decorator>, String)>,
    pub funcs: Vec<Func>
}

/// A top-level item. Can either be a type definition, or an interface.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
pub enum Def {
    Type(TypeDef),
    Interface(Interface),
}

/// The context returned by a successful parse. Contains convenient hashmaps
/// to access types and interfaces from their fully qualified name.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct Ctx {
    pub types: HashMap<String, TypeDef>,
    pub interfaces: HashMap<String, Interface>
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_comment(parent: &mut Pairs<Rule>) -> String {
    let mut comment = String::new();

    while let Some(s) = parent.peek() {
        if s.as_rule() == Rule::comment {
            comment += s.as_str()[1..].trim();
            comment += "\n";
            let _ = parent.next();
        } else {
            break;
        }
    }
    comment
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_name<'a>(parent: &mut Pairs<'a, Rule>) -> &'a str {
    let name = parent.next().unwrap();
    match name.as_rule() {
        Rule::name | Rule::sname | Rule::iname => (),
        rule => panic!("{:?} != name or sname: Broken parser: {} is not a name", rule, name)
    }
    name.as_str()
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_number(parent: &mut Pairs<Rule>) -> u64 {
    let num = parent.next().unwrap();
    assert_eq!(num.as_rule(), Rule::number, "Broken parser: {:?} is not a number", num);

    if num.as_str().starts_with("0x") {
        u64::from_str_radix(&num.as_str()[2..], 16).unwrap()
    } else {
        num.as_str().parse().unwrap()
    }
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_struct(mut ty: Pairs<Rule>) -> Struct {
    // Template is optional.
    let size = match ty.peek().unwrap().as_rule() {
        Rule::structTemplate => {
            let mut num_rule = ty.next().unwrap().into_inner();
            let num = parse_number(&mut num_rule);
            assert_eq!(num_rule.next(), None);
            Some(num)
        },
        _ => None
    };

    let mut fields = Vec::new();

    for item in ty {
        assert_eq!(item.as_rule(), Rule::structField, "Broken parser: struct[1..] is not structField");
        let mut items = item.into_inner();

        let doc = parse_comment(&mut items);
        let ty = parse_type(&mut items);
        let name = parse_name(&mut items);

        fields.push((doc, name.into(), ty));
    }

    Struct {
        size,
        fields,
    }
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_enum(mut ty: Pairs<Rule>) -> Enum {
    let tyname = parse_name(&mut ty).to_string();

    let mut fields = Vec::new();

    for item in ty {
        assert_eq!(item.as_rule(), Rule::enumField, "Broken parser: enum[1..] is not enumFields");
        let mut items = item.into_inner();

        let doc = parse_comment(&mut items);
        let name = parse_name(&mut items);
        let num = parse_number(&mut items);

        fields.push((doc, name.into(), num));
    }

    Enum {
        tyname,
        fields,
    }
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_alias(mut ty: Pairs<Rule>) -> Alias {
    let aliaspair = ty.peek().unwrap();
    let ret = match aliaspair.as_rule() {
        Rule::aliasArray => {
            let mut inner = ty.next().unwrap().into_inner();
            let alias = inner.next().unwrap();
            assert_eq!(alias.as_rule(), Rule::alias, "Broken parser: this is not an alias: {:?}", alias);
            let nextalias = parse_alias(alias.into_inner());
            let num = parse_number(&mut inner);
            assert!(inner.next().is_none(), "Broken parser: alias has more than 2 template args: {:?}", inner);
            Alias::Array(Box::new(nextalias), num)
        },
        Rule::aliasBuffer => {
            let mut inner = ty.next().unwrap().into_inner();
            let alias = inner.next().unwrap();
            assert_eq!(alias.as_rule(), Rule::alias, "Broken parser: this is not an alias: {:?}", alias);
            let nextalias = parse_alias(alias.into_inner());
            let num1 = parse_number(&mut inner);
            let num2 = parse_number(&mut inner);
            assert!(inner.next().is_none(), "Broken parser: alias has more than 3 template args: {:?}", inner);
            Alias::Buffer(Box::new(nextalias), num1, num2)

        },
        Rule::aliasObject => {
            let mut inner = ty.next().unwrap().into_inner();
            let name = parse_name(&mut inner).to_string();
            assert!(inner.next().is_none(), "Broken parser: alias has more than 1 template args: {:?}", inner);
            Alias::Object(name)
        },
        Rule::aliasBytes => {
            let mut inner = ty.next().unwrap().into_inner();
            let size = parse_number(&mut inner);
            assert!(inner.next().is_none(), "Broken parser: alias has more than 1 template args: {:?}", inner);
            Alias::Bytes(size)
        },
        Rule::aliasAlign => {
            let mut inner = ty.next().unwrap().into_inner();
            let num = parse_number(&mut inner);
            let alias = inner.next().unwrap();
            assert_eq!(alias.as_rule(), Rule::alias, "Broken parser: this is not an alias: {:?}", alias);
            let nextalias = parse_alias(alias.into_inner());
            assert!(inner.next().is_none(), "Broken parser: alias has more than 2 template args: {:?}", inner);
            Alias::Align(num, Box::new(nextalias))
        },
        Rule::aliasHandle => {
            let mut inner = ty.next().unwrap().into_inner();
            let is_copy_rule = inner.next().unwrap();
            assert_eq!(is_copy_rule.as_rule(), Rule::handleIsCopy);
            let is_copy = is_copy_rule.as_str() == "copy";
            let ty = inner.next().map(|v| {
                assert_eq!(v.as_rule(), Rule::handleType);
                match v.as_str() {
                    "process"              => HandleType::Process,
                    "thread"               => HandleType::Thread,
                    "debug"                => HandleType::Debug,
                    "code_memory"          => HandleType::CodeMemory,
                    "transfer_memory"      => HandleType::TransferMemory,
                    "shared_memory"        => HandleType::SharedMemory,
                    "server_port"          => HandleType::ServerPort,
                    "client_port"          => HandleType::ClientPort,
                    "server_session"       => HandleType::ServerSession,
                    "client_session"       => HandleType::ClientSession,
                    "server_light_session" => HandleType::ServerLightSession,
                    "client_light_session" => HandleType::ClientLightSession,
                    "readable_event"       => HandleType::ReadableEvent,
                    "writable_event"       => HandleType::WritableEvent,
                    "irq_event"            => HandleType::IrqEvent,
                    "device_address_space" => HandleType::DeviceAddressSpace,
                    _ => unreachable!()
                }
            });
            Alias::Handle(is_copy, ty)
        },
        Rule::aliasPid => { ty.next().unwrap(); Alias::Pid },
        Rule::iname => Alias::Other(parse_name(&mut ty).to_string()),
        rule => panic!("Unexpected rule {:?} at {:?}", rule, aliaspair)
    };
    assert!(ty.next().is_none());

    ret
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_type(parent: &mut Pairs<Rule>) -> Type {
    let ty = parent.next().unwrap();
    assert_eq!(ty.as_rule(), Rule::ty);
    let mut ty = ty.into_inner();

    let inner = ty.next().unwrap();
    assert!(ty.next().is_none(), "Broken parser: type has more than 1 element: {:?}", ty);

    match inner.as_rule() {
        Rule::structure => {
            Type::Struct(parse_struct(inner.into_inner()))
        },
        Rule::enumeration => {
            Type::Enum(parse_enum(inner.into_inner()))
        },
        Rule::alias => {
            Type::Alias(parse_alias(inner.into_inner()))
        },
        _ => unreachable!()
    }
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_type_def(mut typedef: Pairs<Rule>) -> TypeDef {
    let doc = parse_comment(&mut typedef);
    let name = parse_name(&mut typedef);
    let ty = parse_type(&mut typedef);

    TypeDef {
        doc,
        name: name.into(),
        ty
    }
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_service_name_list(parent: &mut Pairs<Rule>) -> Vec<(Vec<Decorator>, String)> {
    let service_list = parent.next().unwrap();
    assert_eq!(service_list.as_rule(), Rule::serviceNameList);

    let mut ret = Vec::new();
    let mut inner = service_list.into_inner();
    while inner.peek().is_some() {
        let decorators = parse_decorators(&mut inner);
        let item = inner.next().unwrap();
        assert_eq!(item.as_rule(), Rule::sname);
        ret.push((decorators, item.as_str().into()));
    }
    ret
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_version_number(parent: &mut Pairs<Rule>) -> String {
    let version_number = parent.next().unwrap();
    assert_eq!(version_number.as_rule(), Rule::versionNumber);

    let mut version_number = version_number.into_inner();
    let one = parse_number(&mut version_number);
    let two = parse_number(&mut version_number);
    let three = parse_number(&mut version_number);

    format!("{}.{}.{}", one, two, three)
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_decorators(parent: &mut Pairs<Rule>) -> Vec<Decorator> {
    let mut decorators = Vec::new();

    while let Some(s) = parent.peek() {
        if s.as_rule() == Rule::decorator {
            let mut s = parent.next().unwrap().into_inner();
            let inner = s.next().unwrap();
            assert!(s.next().is_none(), "Decorator has multiple inner types");
            match inner.as_rule() {
                Rule::versionDecorator => {
                    let mut inner = inner.into_inner();
                    let version_start = parse_version_number(&mut inner);
                    let version_end = inner.peek();
                    let version_end = match version_end.map(|v| v.as_rule()) {
                        Some(Rule::versionPlus) => {
                            None
                        },
                        Some(Rule::versionNumber) => {
                            Some(parse_version_number(&mut inner))
                        },
                        None => {
                            Some(version_start.clone())
                        },
                        _ => unreachable!()
                    };
                    decorators.push(Decorator::Version(version_start, version_end))
                },
                Rule::undocumentedDecorator => {
                    decorators.push(Decorator::Undocumented);
                },
                Rule::managedportDecorator => {
                    decorators.push(Decorator::ManagedPort);
                },
                Rule::unknownDecorator => {
                    let mut inner = inner.into_inner();
                    let name = parse_name(&mut inner).to_string();
                    let args = parse_name(&mut inner).to_string();
                    decorators.push(Decorator::Unknown(name, args));
                },
                _ => unreachable!()
            }
        } else {
            break;
        }
    }

    decorators
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_named_type(named_type: Pair<Rule>) -> (Alias, Option<String>) {
    let mut named_type = named_type.into_inner();

    let alias = named_type.next().unwrap();
    assert_eq!(alias.as_rule(), Rule::alias, "Broken parser: this is not an alias: {:?}", alias);
    let ty = parse_alias(alias.into_inner());
    let name = if named_type.peek().is_some() {
        Some(parse_name(&mut named_type).into())
    } else {
        None
    };

    assert!(named_type.next().is_none());

    (ty, name)
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_named_tuple(parent: &mut Pairs<Rule>) -> Vec<(Alias, Option<String>)> {
    let named_tuple = parent.next().unwrap();
    assert_eq!(named_tuple.as_rule(), Rule::namedTuple);

    let mut ret = Vec::new();
    for item in named_tuple.into_inner() {
        assert_eq!(item.as_rule(), Rule::namedType);
        ret.push(parse_named_type(item));
    }

    ret
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_func(func: Pair<Rule>) -> Func {
    assert_eq!(func.as_rule(), Rule::funcDef, "Broken parser: this is not a function: {:?}", func);

    let mut func = func.into_inner();
    let doc = parse_comment(&mut func);
    let decorators = parse_decorators(&mut func);
    let num = parse_number(&mut func);
    let name = parse_name(&mut func);
    let args = parse_named_tuple(&mut func);
    let ret = match func.peek().map(|v| v.as_rule()) {
        Some(Rule::namedType) => vec![parse_named_type(func.next().unwrap())],
        Some(Rule::namedTuple) => parse_named_tuple(&mut func),
        None => Vec::new(),
        _ => unreachable!()
    };

    Func {
        doc,
        decorators,
        num,
        name: name.into(),
        args,
        ret,
    }
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_interface(mut interface: Pairs<Rule>) -> Interface {
    let doc = parse_comment(&mut interface);
    let name = parse_name(&mut interface);
    let service_list = match interface.peek().map(|v| v.as_rule()) {
        Some(Rule::serviceNameList) => parse_service_name_list(&mut interface),
        _ => Vec::new(),
    };

    let mut funcs = Vec::new();

    for func in interface {
        funcs.push(parse_func(func));
    }

    Interface {
        doc,
        name: name.into(),
        service_list,
        funcs
    }
}

#[allow(clippy::missing_docs_in_private_items)]
fn parse_def(mut def: Pairs<Rule>) -> Def {
    let inner = def.next().unwrap();
    assert!(def.next().is_none(), "Broken parser: type has more than 1 element");

    match inner.as_rule() {
        Rule::typeDef => {
            Def::Type(parse_type_def(inner.into_inner()))
        },
        Rule::interface => {
            Def::Interface(parse_interface(inner.into_inner()))
        },
        _ => unreachable!()
    }
}

/// Parse the given string into a SwIPC [Ctx].
pub fn parse(s: &str) -> Ctx {
    let mut ctx = Ctx {
        types: HashMap::new(),
        interfaces: HashMap::new(),
    };

    let rule = match SwipcParser::parse(Rule::start, &s) {
        Ok(mut rule) => rule.next().unwrap(),
        Err(err) => {
            panic!("Failed to parse:\n{}", err);
        }
    };

    for def in rule.into_inner() {
        match def.as_rule() {
            Rule::def => match parse_def(def.into_inner()) {
                // TODO: SwIPC-parser: Merge multiple type/interface definition
                // BODY: When the parser encounters multiple definitions of a type
                // BODY: or interface, it should try to merge them into a single
                // BODY: one.
                // BODY:
                // BODY: This will make it easier to implement the logic of
                // BODY: merging auto.id and switchbrew.id: we can just treat
                // BODY: them as one big file, merging every entry, keeping the
                // BODY: "best" information of each, while ensuring they are
                // BODY: compatible.
                Def::Type(tydef) => { ctx.types.insert(tydef.name.clone(), tydef); },
                Def::Interface(iface) => { ctx.interfaces.insert(iface.name.clone(), iface); },
            }
            Rule::EOI => (),
            rule => unreachable!("{:?}", rule),
        }
    }

    ctx
}
