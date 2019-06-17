//! Mod parser
//!
//! Syn's `mod` parser is only available in `full` mode, which takes forever to
//! compile. So let's write our own little parser. The main reason why `mod` is
//! only available in `full` mode is because it requires parsing the content of
//! the `mod` block. In our case, we'll simply return the block as a
//! TokenStream, removing the need to parse it.
//!
//! Note that this still needs the "derive" feature.

use syn::{self, token, Token, Attribute, Visibility, Ident, braced, AttrStyle};
use syn::token::Brace;
use syn::parse::{Parse, ParseStream};
use proc_macro2::TokenStream;
use quote::{ToTokens, TokenStreamExt};

pub struct ItemMod {
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub mod_token: Token![mod],
    pub ident: Ident,
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

impl ToTokens for ItemMod {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        fn is_outer(attr: &&Attribute) -> bool {
            match attr.style {
                AttrStyle::Outer => true,
                _ => false,
            }
        }
        tokens.append_all(self.attrs.iter().filter(is_outer));
        self.vis.to_tokens(tokens);
        self.mod_token.to_tokens(tokens);
        self.ident.to_tokens(tokens);
        if let Some((ref brace, ref items)) = self.content {
            brace.surround(tokens, |tokens| {
                fn is_inner(attr: &&Attribute) -> bool {
                    match attr.style {
                        AttrStyle::Inner(_) => true,
                        _ => false,
                    }
                }
                tokens.append_all(self.attrs.iter().filter(is_inner));
                tokens.append_all(items.clone().into_iter());
            });
        } else {
            match self.semi {
                Some(ref t) => t.to_tokens(tokens),
                None => <Token![;]>::default().to_tokens(tokens)
            }
        }
    }
}