//! Mod parser
//!
//! Syn's `mod` parser is only available in `full` mode, which takes forever to
//! compile. So let's write our own little parser. The main reason why `mod` is
//! only available in `full` mode is because it requires parsing the content of
//! the `mod` block. In our case, we'll simply return the block as a
//! TokenStream, removing the need to parse it.
//!
//! Note that this still needs the "derive" feature.

use syn::{self, token, Token, Attribute, Visibility, Ident, braced};
use syn::token::Brace;
use syn::parse::{Parse, ParseStream};
use proc_macro2::TokenStream;

/// A module or module declaration: `mod m` or `mod m { ... }`.
///
/// Doesn't attempt to parse the content, in order to keep the requirement on
/// `syn` down.
///
/// *This type is available if Syn is built with the "derive" feature.*
#[allow(clippy::missing_docs_in_private_items)] // Those are all bloody obvious.
pub struct ItemMod {
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub mod_token: Token![mod],
    pub ident: Ident,
    /// Optional content of the module. The TokenStream contains whatever tokens
    /// are between the braces.
    pub content: Option<(Brace, TokenStream)>,
    pub semi: Option<Token![;]>,
}

impl Parse for ItemMod {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let outer_attrs = input.call(Attribute::parse_outer)?;
        let vis: Visibility = input.parse()?;
        let mod_token: Token![mod] = input.parse()?;
        let ident: Ident = input.parse()?;

        let lookahead = input.lookahead1();
        if lookahead.peek(Token![;]) {
            Ok(ItemMod {
                attrs: outer_attrs,
                vis: vis,
                mod_token: mod_token,
                ident: ident,
                content: None,
                semi: Some(input.parse()?),
            })
        } else if lookahead.peek(token::Brace) {
            let content;
            let brace_token = braced!(content in input);
            let inner_attrs = content.call(Attribute::parse_inner)?;

            let items = content.cursor().token_stream();
            let mut attrs = outer_attrs;
            attrs.extend(inner_attrs);

            Ok(ItemMod {
                attrs: attrs,
                vis: vis,
                mod_token: mod_token,
                ident: ident,
                content: Some((brace_token, items)),
                semi: None,
            })
        } else {
            Err(lookahead.error())
        }
    }
}
