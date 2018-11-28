/// Auto derive Object.
///
/// Takes a service implementation as a parameter, and auto-derives Object,
/// generating the dispatcher logic. The syntax for using it is as under:
///
/// ```rust
/// struct Service;
/// object! {
///     impl Service {
///         #[cmdid(0)]
///         fn test(&mut self, val: u32,) -> Result<(u32,), usize> {
///             Ok((0,))
///         }
///     }
/// }
/// ```
///
/// Allowed argument types:
/// - Pid: the Pid of the remote process, from the Handle Descriptor
/// - Handle<move>: A Handle in the Handle Descriptor's move handle list.
/// - Handle<copy>: A Handle in the Handle Descriptor's copy handle list.
// TODO: Input Object! We should be able to take an ObjectWrapper<T: IObject>
/// - InBuffer/OutBuffer/InPointer/OutPointer: Equivalent to A/B/C/X buffers.
/// - T where T: Copy, Clone, repr(C): passed through Raw Data.
///
/// Allowed return types:
/// - Pid: The current Pid, from the Handle Descriptor.
/// - Handle: A Handle in the Handle Descriptor's move handle list.
/// - HandleRef: A Handle in the Handle Descriptor's copy handle list.
/// - <T: IObject>: An Object that will be added to the current
///   WaitableManager for processing. Either added to the Handle Descriptor copy
///   handle list, or as a domain object
/// - T where T: Copy, Clone, repr(C): passed through Raw Data.
///
/// Important note: the return value **has** to be a `Result<(Type,...), usize>`.
/// The function *must* take &mut self as a first argument. And right now, as a
/// small caveat, the argument list and return tuple list must end with a coma.
///
/// The implementation will be left verbatim (except for the cmdid). A separate
/// `impl Object for Service` block will be generated.
///
/// This macro is deeply recursive. If used, you'll likely need to add
/// `#![recursion_limit = "1024"]` - or more - to your crate root.
//
// Note to maintainers: This macro uses a few powerful patterns:
// - Incremental TT Muncher
// - Internal Rules
// - Push-Down Accumulation
// I highly recommend reading through https://danielkeep.github.io/tlborm/book
// before diving into this abomination.
//
// Also, to future me: Yes, generating from SwIPC would've been a much better
// idea. But where's the fun in that?
#[macro_export]
macro_rules! object {
    // Top level match arm. Matches the typename. Generates an impl block that
    // will copy the input block almost verbatim - simply removing the cmdid. And
    // separately generates an impl Object for Service block that will contain
    // the dispatch method.
    (impl $tyname:ident {
        $($fns:tt)*
    }) => {
        impl $tyname {
            object!(@functions meta=(), $($fns)*);
        }

        impl $crate::ipc::server::Object for $tyname {
            fn dispatch(&mut self, cmdid: u32, buf: &mut [u8]) -> Result<(), usize> {
                //object!(@enum $($fns)*)
                object!(@dispatch self, cmdid=cmdid, buf=buf, fns=(), $($fns)*)
            }
        }
    };

    // ------------------ Function Block -----------------
    // We're processing each function, one by one. The goal of this block is to
    // remove the #[cmdid(0)] block that would be invalid if left alone.
    // This block has one argument, meta, which is a list of function meta items
    // to output with the function.

    // Start by checking for a cmdid block. If we find one, skip it.
    (@functions meta=($($meta:meta),*), #[cmdid($expr:expr)] $($tt:tt)*) => {
        object!(@functions meta=($($meta),*), $($tt)*);
    };
    // If we find any other kind of meta parameter, accumulate it in the meta
    // list. Note the use of a small trick: we match using $(meta),*, and then
    // repeat with $(meta,)*. This adds a trailing coma if the list was not
    // empty. THis pattern will be used throughout the macro.
    (@functions meta=($($meta:meta),*), #[$fmeta:meta] $($tt:tt)*) => {
        object!(@functions meta=($($meta,)* $fmeta), $($tt)*);
    };
    // Match the actual function. Some limitations:
    // - The function cannot be generic.
    //
    // Outputs the function, resets the meta list, and go to the next function.
    (@functions meta=($($meta:meta),*), fn $funcname:ident $(<$($lifetime:lifetime),*>)* (&mut $self:ident, $($args:tt)*) -> Result<($($ret:tt)*), usize> $body:block $($tt:tt)*) => {
        object!(@rewriteargs ($($meta),*), $funcname, ($($($lifetime),*)*), $self, (), ($($ret)*), $body, $($args)*);
        object!(@functions meta=(), $($tt)*);
    };
    // All functions have been processed. We can now stop parsing.
    (@functions meta=(), ) => {};

    // ------------------ Arg Rewriting Block ------------
    // We're going to do some light processing on arguments to remove some invalid
    // syntax. We want to turn Handle<move> and Handle<copy> into Handle.
    //
    // Note: we're taking self as an independant parameter to make sure we don't
    // break hygiene.
    (@rewriteargs ($($meta:meta),*), $funcname:ident, ($($lifetime:lifetime),*), $self:ident, ($($argname:ident : $argty:ty),*), ($($ret:tt)*), $body:block, $name:ident : Handle<copy>, $($rest:tt)*) => {
        object!(@rewriteargs ($($meta:meta),*), $funcname, ($($lifetime),*), $self, ($($argname: $argty,)* $name: Handle), ($($ret)*), $body, $($rest)*);
    };
    (@rewriteargs ($($meta:meta),*), $funcname:ident, ($($lifetime:lifetime),*), $self:ident, ($($argname:ident : $argty:ty),*), ($($ret:tt)*), $body:block, $name:ident : Handle<move>, $($rest:tt)*) => {
        object!(@rewriteargs ($($meta:meta),*), $funcname, ($($lifetime),*), $self, ($($argname: $argty,)* $name: Handle), ($($ret)*), $body, $($rest)*);
    };
    (@rewriteargs ($($meta:meta),*), $funcname:ident, ($($lifetime:lifetime),*), $self:ident, ($($argname:ident : $argty:ty),*), ($($ret:tt)*), $body:block, $name:ident : $ty:ty, $($rest:tt)*) => {
        object!(@rewriteargs ($($meta:meta),*), $funcname, ($($lifetime),*), $self, ($($argname: $argty,)* $name: $ty), ($($ret)*), $body, $($rest)*);
    };
    (@rewriteargs ($($meta:meta),*), $funcname:ident, ($($lifetime:lifetime),*), $self:ident, ($($args:tt)*), ($($ret:tt)*), $body:block, ) => {
        $(#[$meta])*
        fn $funcname <$($lifetime),*> (&mut $self, $($args)*) -> Result<($($ret)*), usize> $body
    };


    // ------------------ Dispatch Block -----------------
    // We're processing each function again, one by one. The goal of this block
    // is to generate a big match on the cmdid, where each block contains the
    // IPC buffer parsing code, calls the associated function, and packs the
    // returned values to the IPC buffer.
    //
    // This function takes 6 arguments:
    // - sel: A &mut self. Used to call the function (because of
    //        macro hygiene rules, we can't just hardcode "self").
    // - cmdid: The cmdid we need to generate the match block on. Comes from the
    //          dispatch arguments (again, this is working around hygiene).
    // - buf: A &mut [u8], the IPC buffer we parse from and pack to. Again,
    //        hygiene.
    // - fns: A list of cmdid => block, basically the arms of the generated
    //        match. Should be initially empty, will be accumulated through
    //        recursion.

    // Again, let's start by looking for a cmdid block. If we find one, save it
    // as a new fcmdid argument.
    (@dispatch $sel:expr, cmdid=$cmdid:expr, buf=$buf:expr, fns=($($fns:tt)*), #[cmdid($fcmdid:expr)] $($tt:tt)*) => {
        object!(@dispatch $sel, cmdid=$cmdid, buf=$buf, fns=($($fns)*), fcmdid=$fcmdid, $($tt)*);
    };
    // If we find any other meta item before cmdid, skip it.
    (@dispatch $sel:expr, cmdid=$cmdid:expr, buf=$buf:expr, fns=($($fns:tt)*), #[$fmeta:meta] $($tt:tt)*) => {
        object!(@dispatch $sel, cmdid=$cmdid, buf=$buf, fns=($($fns)*), $($tt)*);
    };
    // If we find any other meta item after cmdid, skip it.
    (@dispatch $sel:expr, cmdid=$cmdid:expr, buf=$buf:expr, fns=($($fns:tt)*), fcmdid=$fcmdid:expr, #[$fmeta:meta] $($tt:tt)*) => {
        object!(@dispatch $sel, cmdid=$cmdid, buf=$buf, fns=($($fns)*), fcmdid=$fcmdid, $($tt)*);
    };
    // Match the actual function. Add to the fns list a new cmdid => block item
    // for the currently matched function (this is the $cufcmdid => {} block).
    // This block will contain the actual parsing code.
    //
    // Refer to the comments in the macro for how it works inside the hood.
    (@dispatch $sel:expr, cmdid=$cmdid:expr, buf=$buf:expr, fns=($($fcmdid:expr => $fcmdfn:block),*), fcmdid=$curfcmdid:expr,
       fn $funcname:ident $(<$($lifetime:lifetime),*>)* (&mut self, $($args:tt)*) -> Result<($($ret:tt)*), usize> $body:block $($tt:tt)*) => {
        // Recursively call ourselves with the next function, adding a new cmdid => block to the fns aggregation.
        object!(@dispatch $sel, cmdid=$cmdid, buf=$buf, fns=($($fcmdid => $fcmdfn,)* $curfcmdid => {
            // In this block, we start by generating a `struct Args` that will
            // contain all the *raw* arguments.
            object!(@genstruct Args fields=(), $($args)*);
            // We then parse the IPC buffer.
            let mut msgin = $crate::ipc::Message::<Args, [_; object!(@bufcount $($args)*)],
                                            [_; object!(@copycount $($args)*)],
                                            [_; object!(@movecount $($args)*)]>::unpack($buf);
            // This will generate the self.function(); invocation with all the
            // correct arguments popped from the msgin struct.
            let ret = object!(@callargs $sel, funcname=$funcname, msgin=msgin, args=(), $($args)*);
            // We now want to create the msgout. Basically the same as msgin, but
            // using the return types instead. Note that bufcount and co work on
            // both name: ty, and ty, lists.
            let mut msgout = $crate::ipc::Message::<_, [_; object!(@bufcount $($ret)*)],
                                          [_; object!(@copycount $($ret)*)],
                                          [_; object!(@movecount $($ret)*)]>::new_response(msgin.token());
            // Finally, generate the struct Ret (which we elided above), and push
            // all the arguments to msgout.
            match ret {
                Ok(ret) => object!(@genret fields=(), retfields=(), msgout, ret, $($ret)*),
                Err(err) => { msgout.set_error(err as u32); }
            }
            // Pack the message to msgout and we're done :D
            msgout.pack($buf);
            Ok(())
        }), $($tt)*);
    };
    // We parsed all the functions \o/. All that's left to do is taking the fns
    // list, and creating a big match from it.
    (@dispatch $sel:expr, cmdid=$cmdid:expr, buf=$buf:expr, fns=($($fcmdid:expr => $fcmd:block),*), ) => {
        match $cmdid {
            $($fcmdid => $fcmd,)*
            cmd => {
                let _ = $crate::syscalls::output_debug_string(&format!("Unknown cmdid: {}", cmd));
                Err(0xF601)
            }
        }
    };

    // -------------- Arg Structure Gen ------------------
    // We now want to be generating the argument struct. This is a fairly "easy"
    // macro. It will generate a structure that contains a field for every raw
    // argument (it will skip over IPC Buffers, Handles and Pid).
    //
    // It has 1 argument: fields, a list of `ident: ty`, the fields of our
    // structure. It should be initially empty.
    //
    // One kind of annoying restrictions of rust macros: a $ty cannot be followed
    // by a $tt. This is, from what I'm told, for two reasons: 1. it can be
    // ambiguous (Do we match Result or Result<()> ?) and 2. future extensions
    // could change the syntax of a type.
    //
    // The end-result, though, is that we need a delimiter. The coma will do
    // that job - but it means our argument list *must* end with a coma (OR, I
    // guess I could also duplicate all the rules, but removing the `, $($tt)*`
    // bit - to handle the "we're the last argument" case. But this macro is
    // already large enough).

    // Let's skip all the non-raw types.
    (@genstruct $ident:ident fields=($($args:tt)*), $name:ident: InBuffer<$ty:ty>, $($tt:tt)*) => {
        object!(@genstruct $ident fields=($($args)*), $($tt)*)
    };
    // Let's skip all the non-raw types.
    (@genstruct $ident:ident fields=($($args:tt)*), $name:ident: OutBuffer<$ty:ty>, $($tt:tt)*) => {
        object!(@genstruct $ident fields=($($args)*), $($tt)*)
    };
    // Let's skip all the non-raw types.
    (@genstruct $ident:ident fields=($($args:tt)*), $name:ident: InPointer<$ty:ty>, $($tt:tt)*) => {
        object!(@genstruct $ident fields=($($args)*), $($tt)*)
    };
    // Let's skip all the non-raw types.
    (@genstruct $ident:ident fields=($($args:tt)*), $name:ident: OutPointer<$ty:ty>, $($tt:tt)*) => {
        object!(@genstruct $ident fields=($($args)*), $($tt)*)
    };
    // Let's skip all the non-raw types.
    (@genstruct $ident:ident fields=($($args:tt)*), $name:ident: Handle<move>, $($tt:tt)*) => {
        object!(@genstruct $ident fields=($($args)*), $($tt)*)
    };
    // Let's skip all the non-raw types.
    (@genstruct $ident:ident fields=($($args:tt)*), $name:ident: Handle<copy>, $($tt:tt)*) => {
        object!(@genstruct $ident fields=($($args)*), $($tt)*)
    };
    // Let's skip all the non-raw types.
    (@genstruct $ident:ident fields=($($args:tt)*), $name:ident: Pid, $($tt:tt)*) => {
        object!(@genstruct $ident fields=($($args)*), $($tt)*)
    };
    // Match a raw type! We want to add it to the fields list, as $name: $ty.
    // We again use the same old trick to append a coma if the list is non-empty.
    (@genstruct $ident:ident fields=($($iname:ident: $ity:ty),*), $name:ident: $ty:ty, $($tt:tt)*) => {
        object!(@genstruct $ident fields=($($iname: $ity,)* $name: $ty), $($tt)*)
    };
    // We're done parsing all the arguments. Generate the actual structure.
    //
    // Note: It should be repr(C) to ensure correct ordering, alignment, etc...
    // We also make it derive Debug to ease debugging, and Clone of Copy out of
    // requirement.
    (@genstruct $ident:ident fields=($($name:ident: $ty:ty),*), ) => {
        #[repr(C)]
        #[derive(Default, Debug, Clone, Copy)]
        struct $ident {
            $($name: $ty),*
        }
    };

    // ------------- IPC Implementation Call --------------
    // We're now all ready to call the underlying IPC function implementation.
    // Depending on the input type, we'll want to call different methods from
    // msgin.
    //
    // Takes 4 arguments:
    //
    // - sel: a &mut self. Hygiene.
    // - funcname: The name of the underlying function implementation.
    // - msgin: the Message we'll pop our arguments from. Hygiene.
    // - args: A list of expressions that will be accumulated into, containing
    //         the arguments. Initially empty.
    //
    // TODO: an input HandleRef makes no sense. Ideally, I'd have Handle<copy>
    // and Handle<move>, and would remove the <copy> and <move> from the input?
    // Alternatively, have a HandleCopy and HandleMove types, but meh.

    // We got an InBuffer (type A). Let's call pop_in_buffer.
    (@callargs $sel:expr, funcname=$funcname:ident, msgin=$msgin:expr, args=($($arg:expr),*), $name:ident: InBuffer<$ty:ty>, $($tt:tt)*) => {
        object!(@callargs $sel, funcname=$funcname, msgin=$msgin, args=($($arg,)* $msgin.pop_in_buffer::<$ty>()), $($tt)*);
    };
    // We got an OutBuffer (type B). Let's call pop_out_buffer.
    (@callargs $sel:expr, funcname=$funcname:ident, msgin=$msgin:expr, args=($($arg:expr),*), $name:ident: OutBuffer<$ty:ty>, $($tt:tt)*) => {
        object!(@callargs $sel, funcname=$funcname, msgin=$msgin, args=($($arg,)* $msgin.pop_out_buffer::<$ty>()), $($tt)*);
    };
    // We got an InPointer (type X). Let's call pop_in_pointer.
    (@callargs $sel:expr, funcname=$funcname:ident, msgin=$msgin:expr, args=($($arg:expr),*), $name:ident: InPointer<$ty:ty>, $($tt:tt)*) => {
        object!(@callargs $sel, funcname=$funcname, msgin=$msgin, args=($($arg,)* $msgin.pop_in_pointer::<$ty>()), $($tt)*);
    };
    // We got an OutPointer (type C). Let's call pop_out_pointer.
    (@callargs $sel:expr, funcname=$funcname:ident, msgin=$msgin:expr, args=($($arg:expr),*), $name:ident: OutPointer<$ty:ty>, $($tt:tt)*) => {
        object!(@callargs $sel, funcname=$funcname, msgin=$msgin, args=($($arg,)* $msgin.pop_out_pointer::<$ty>()), $($tt)*);
    };
    // We got a Handle. Let's call pop_handle_move.
    (@callargs $sel:expr, funcname=$funcname:ident, msgin=$msgin:expr, args=($($arg:expr),*), $name:ident: Handle<move>, $($tt:tt)*) => {
        object!(@callargs $sel, funcname=$funcname, msgin=$msgin, args=($($arg,)* $msgin.pop_handle_move()), $($tt)*);
    };
    (@callargs $sel:expr, funcname=$funcname:ident, msgin=$msgin:expr, args=($($arg:expr),*), $name:ident: Handle<copy>, $($tt:tt)*) => {
        object!(@callargs $sel, funcname=$funcname, msgin=$msgin, args=($($arg,)* $msgin.pop_handle_copy()), $($tt)*);
    };
    // We got a Pid. Let's call pop_pid.
    (@callargs $sel:expr, funcname=$funcname:ident, msgin=$msgin:expr, args=($($arg:expr),*), $name:ident: Pid, $($tt:tt)*) => {
        object!(@callargs $sel, funcname=$funcname, msgin=$msgin, args=($($arg,)* $msgin.pop_pid()), $($tt)*);
    };
    // We got any other type. We want to recover it from the raw() structure. See
    // @genargs for more information about how the raw structure looks like.
    (@callargs $sel:expr, funcname=$funcname:ident, msgin=$msgin:expr, args=($($arg:expr),*), $name:ident: $ty:ty, $($tt:tt)*) => {
        object!(@callargs $sel, funcname=$funcname, msgin=$msgin, args=($($arg,)* $msgin.raw().$name), $($tt)*);
    };
    // We're done parsing everything! Let's generate the actual call.
    (@callargs $sel:expr, funcname=$funcname:ident, msgin=$msgin:expr, args=($($arg:expr),*), ) => {
        $sel.$funcname($($arg),*)
    };

    // -------------- Ret Structure Gen ------------------
    // Now that we called our function, we'll want to parse its return values,
    // in order to pack it. This means generating a new structure! Except this
    // time, we don't have any names for all the fields! And we get a tuple
    // output, but we can't really access the fields easily. We can't really
    // "iterate" on a tuple, can we?
    //
    // For the structure, we'll simply generate a tuple struct. All we care about
    // is that it's repr(C) anyways, and rust is more than happy to generate
    // repr(C) tuple structs, so long as all its fields are C types.
    //
    // For the return value, we'll use destructuring, and weaponize macro hygiene
    // to gain the ability to generate new identifiers for every argument! Small
    // primer for hygiene: every identifier is bound to a context (which is
    // basically "where it was declared"). Two identifiers with the same name but
    // different contexts resolve to two separate instances!
    //
    // In this macro, you'll see "arg" repeated a lot. Keep in mind that, thanks
    // to hygiene, every recursion into object!() generates a new context, and so
    // although all the arguments are called "arg", they all resolve to different
    // variables.
    //
    // A small note: structure field names are not hygienic, which is why we use
    // tuple structs.
    //
    // We take 4 arguments:
    // - fields: A list of ident: ty used by the tuple struct. The ident is the
    //           name of the variable destructured from ret. Initially empty.
    // - retfields: A list of idents => expr used to destructure the $ret tuple,
    //              and push all its values to $msgout. Initially empty.
    // - msgout: The Message we're pushing our variables into. Hygiene.
    // - ret: The tuple result from the IPC function implementation.

    // Parse an InBuffer. Call $msgout.push_in_buffer(arg).
    (@genret fields=($($args:tt)*), retfields=($($rname:ident => $rfn:expr),*), $msgout:expr, $ret:expr, InBuffer<$ty:ty>, $($tt:tt)*) => {
        object!(@genret fields=($($args)*), retfields=($($rname => $rfn,)* arg => $msgout.push_in_buffer(arg)), $msgout, $ret, $($tt)*)
    };
    // Parse an OutBuffer. Call $msgout.push_out_buffer(arg).
    (@genret fields=($($args:tt)*), retfields=($($rname:ident => $rfn:expr),*), $msgout:expr, $ret:expr, OutBuffer<$ty:ty>, $($tt:tt)*) => {
        object!(@genret fields=($($args)*), retfields=($($rname => $rfn,)* arg => $msgout.push_out_buffer(arg)), $msgout, $ret, $($tt)*)
    };
    // Parse an InPointer. Call $msgout.push_in_pointer(arg).
    (@genret fields=($($args:tt)*), retfields=($($rname:ident => $rfn:expr),*), $msgout:expr, $ret:expr, InPointer<$ty:ty>, $($tt:tt)*) => {
        object!(@genret fields=($($args)*), retfields=($($rname => $rfn,)* arg => $msgout.push_in_pointer(arg)), $msgout, $ret, $($tt)*)
    };
    // Parse an OutPointer. Call $msgout.push_out_pointer(arg).
    (@genret fields=($($args:tt)*), retfields=($($rname:ident => $rfn:expr),*), $msgout:expr, $ret:expr, OutPointer<$ty:ty>, $($tt:tt)*) => {
        object!(@genret fields=($($args)*), retfields=($($rname => $rfn,)* arg => $msgout.push_out_pointer(arg)), $msgout, $ret, $($tt)*)
    };
    // Parse a Handle. Call $msgout.push_handle_move(arg).
    (@genret fields=($($args:tt)*), retfields=($($rname:ident => $rfn:expr),*), $msgout:expr, $ret:expr, Handle, $($tt:tt)*) => {
        object!(@genret fields=($($args)*), retfields=($($rname => $rfn,)* arg => $msgout.push_handle_move(arg)), $msgout, $ret, $($tt)*)
    };
    // Parse a HandleRef. Call $msgout.push_handle_copy(arg).
    (@genret fields=($($args:tt)*), retfields=($($rname:ident => $rfn:expr),*), $msgout:expr, $ret:expr, HandleRef<$lifetime:lifetime>, $($tt:tt)*) => {
        object!(@genret fields=($($args)*), retfields=($($rname => $rfn,)* arg => $msgout.push_handle_copy(arg)), $msgout, $ret, $($tt)*)
    };
    // Parse a Pid. Call $msgout.push_pid(arg).
    (@genret fields=($($args:tt)*), retfields=($($rname:ident => $rfn:expr),*), $msgout:expr, $ret:expr, Pid, $($tt:tt)*) => {
        object!(@genret fields=($($args)*), retfields=($($rname => $rfn,)* arg => $msgout.push_pid()), $msgout, $ret, $($tt)*)
    };
    // Parse a raw type. Don't call anything (is (); even a legal statement?).
    // Add the type to the fields list.
    (@genret fields=($($iname:ident: $ity:ty),*), retfields=($($rname:ident => $rfn:expr),*), $msgout:expr, $ret:expr, $ty:ty, $($tt:tt)*) => {
        object!(@genret fields=($($iname: $ity,)* arg: $ty), retfields=($($rname => $rfn,)* arg => ()), $msgout, $ret, $($tt)*)
    };
    // We're done parsing everything. Generate the structure, destructure $ret,
    // call all the functions to push values to msgout, and push_raw.
    (@genret fields=($($name:ident: $ty:ty),*), retfields=($($rname:ident => $rfn:expr),*), $msgout:expr, $ret:expr, ) => {{
        #[repr(C)]
        #[derive(Default, Debug, Clone, Copy)]
        struct Ret($($ty,)*);

        let ($($rname,)*) = $ret;
        $($rfn;)*
        $msgout.push_raw(Ret($($name,)*));
    }};

    // -------------- Counters ---------------------------
    // Some dumb utility macros that are used to count how many of each type of
    // argument there are - so we can configure the ArrayVecs properly.
    // bufcount counts *Buffer, movecount counts Handle<move> or Handle and copycount counts
    // Handle<copy> or HandleRef. I don't think I need to document all the rules, they're fairly
    // straightforward.
    // And yes, [T; 1 + 1 + 1 + 0] is a valid type!
    (@bufcount ) => { 0 };
    (@bufcount InBuffer<$ty:ty>, $($tt:tt)*) => {
        1 + object!(@bufcount $($tt)*)
    };
    (@bufcount OutBuffer<$ty:ty>, $($tt:tt)*) => {
        1 + object!(@bufcount $($tt)*)
    };
    (@bufcount InPointer<$ty:ty>, $($tt:tt)*) => {
        1 + object!(@bufcount $($tt)*)
    };
    (@bufcount OutPointer<$ty:ty>, $($tt:tt)*) => {
        1 + object!(@bufcount $($tt)*)
    };
    (@bufcount $ty:ty, $($tt:tt)*) => {
        object!(@bufcount $($tt)*)
    };
    (@bufcount $name:ident: $($tt:tt)*) => {
        object!(@bufcount $($tt)*);
    };
    
    (@copycount ) => { 0 };
    (@copycount HandleRef, $($tt:tt)*) => {
        1 + object!(@copycount $($tt)*)
    };
    (@copycount Handle<copy>, $($tt:tt)*) => {
        1 + object!(@copycount $($tt)*)
    };
    (@copycount $ty:ty, $($tt:tt)*) => {
        object!(@copycount $($tt)*)
    };
    (@copycount $name:ident: $($tt:tt)*) => {
        object!(@copycount $($tt)*);
    };

    (@movecount) => { 0 };
    (@movecount Handle<move>, $($tt:tt)*) => {
        1 + object!(@movecount $($tt)*)
    };
    (@movecount Handle, $($tt:tt)*) => {
        1 + object!(@movecount $($tt)*)
    };
    (@movecount $ty:path, $($tt:tt)*) => {
        object!(@movecount $($tt)*)
    };
    (@movecount $name:ident: $($tt:tt)*) => {
        object!(@movecount $($tt)*);
    };
}
