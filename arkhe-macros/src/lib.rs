//! Derive macros for ArkheKernel.
//!
//! Three derives, one shared shape:
//! - `#[derive(ArkheAction)]`    — emits `Sealed` + `ActionDeriv`. The
//!   user supplies `impl ActionCompute for T { fn compute ... }`; the
//!   kernel-side blanket
//!   `impl<T: ActionDeriv + ActionCompute> Action for T` provides the
//!   postcard-canonical `canonical_bytes`/`from_bytes`/`approx_size`
//!   defaults.
//! - `#[derive(ArkheComponent)]` — emits `Sealed` + `Component`. No
//!   user method to implement; the trait's default methods (postcard)
//!   handle the data round trip.
//! - `#[derive(ArkheEvent)]`     — emits `Sealed` + `Event`, same shape
//!   as Component. The user type must additionally derive `Debug` plus
//!   `serde::{Serialize, Deserialize}`.
//!
//! Every derive expects `#[arkhe(type_code = N, schema_version = M)]`.
//! `schema_version` defaults to 1 when omitted; `type_code` is mandatory.
//!
//! ```ignore
//! use arkhe_kernel::{ArkheComponent, ArkheEvent};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, ArkheComponent)]
//! #[arkhe(type_code = 5001, schema_version = 1)]
//! struct CounterComponent { value: u64 }
//!
//! #[derive(Debug, Serialize, Deserialize, ArkheEvent)]
//! #[arkhe(type_code = 8001)]
//! struct PostCreatedEvent { author: u64, body: String }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Attribute, DeriveInput, Generics, Ident};

/// `#[arkhe(type_code = N, schema_version = M)]` parsed values.
struct ArkheArgs {
    type_code: u32,
    schema_version: u32,
}

/// Parse `#[arkhe(...)]` attributes on the deriving type. Returns the
/// values, or a `compile_error!` token stream if the attribute is
/// missing/malformed. `schema_version` defaults to 1.
fn parse_arkhe_args(attrs: &[Attribute], target: &Ident) -> Result<ArkheArgs, TokenStream> {
    let mut type_code: Option<u32> = None;
    let mut schema_version: u32 = 1;
    let mut parse_error: Option<syn::Error> = None;

    for attr in attrs {
        if !attr.path().is_ident("arkhe") {
            continue;
        }
        let result = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("type_code") {
                let value = meta.value()?;
                let lit: syn::LitInt = value.parse()?;
                type_code = Some(lit.base10_parse()?);
                return Ok(());
            }
            if meta.path.is_ident("schema_version") {
                let value = meta.value()?;
                let lit: syn::LitInt = value.parse()?;
                schema_version = lit.base10_parse()?;
                return Ok(());
            }
            Err(meta
                .error("unknown #[arkhe(...)] argument; expected `type_code` or `schema_version`"))
        });
        if let Err(e) = result {
            parse_error = Some(e);
            break;
        }
    }

    if let Some(err) = parse_error {
        return Err(err.to_compile_error().into());
    }

    let type_code = match type_code {
        Some(v) => v,
        None => {
            return Err(syn::Error::new_spanned(
                target,
                "missing #[arkhe(type_code = N)] attribute",
            )
            .to_compile_error()
            .into());
        }
    };

    Ok(ArkheArgs {
        type_code,
        schema_version,
    })
}

/// Emit the `Sealed` impl shared by all three derives.
fn sealed_impl(name: &Ident, generics: &Generics) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    quote! {
        impl #impl_generics ::arkhe_kernel::state::traits::_sealed::Sealed
            for #name #ty_generics #where_clause {}
    }
}

/// Derive `Sealed` + `ActionDeriv` for a domain action. Pair with
/// `impl ActionCompute for ...` to satisfy the kernel `Action` blanket.
#[proc_macro_derive(ArkheAction, attributes(arkhe))]
pub fn derive_arkhe_action(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident.clone();
    let args = match parse_arkhe_args(&input.attrs, &name) {
        Ok(a) => a,
        Err(ts) => return ts,
    };
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let sealed = sealed_impl(&name, &input.generics);
    let type_code = args.type_code;
    let schema_version = args.schema_version;

    let expanded = quote! {
        #sealed

        impl #impl_generics ::arkhe_kernel::state::traits::ActionDeriv
            for #name #ty_generics #where_clause
        {
            const TYPE_CODE: ::arkhe_kernel::abi::TypeCode =
                ::arkhe_kernel::abi::TypeCode(#type_code);
            const SCHEMA_VERSION: u32 = #schema_version;
        }
    };

    TokenStream::from(expanded)
}

/// Derive `Sealed` + `Component`. Default trait methods (postcard) cover
/// `canonical_bytes` / `from_bytes` / `approx_size` — no user method
/// required beyond `serde::{Serialize, Deserialize}` derives.
#[proc_macro_derive(ArkheComponent, attributes(arkhe))]
pub fn derive_arkhe_component(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident.clone();
    let args = match parse_arkhe_args(&input.attrs, &name) {
        Ok(a) => a,
        Err(ts) => return ts,
    };
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let sealed = sealed_impl(&name, &input.generics);
    let type_code = args.type_code;
    let schema_version = args.schema_version;

    let expanded = quote! {
        #sealed

        impl #impl_generics ::arkhe_kernel::state::traits::Component
            for #name #ty_generics #where_clause
        {
            const TYPE_CODE: ::arkhe_kernel::abi::TypeCode =
                ::arkhe_kernel::abi::TypeCode(#type_code);
            const SCHEMA_VERSION: u32 = #schema_version;
        }
    };

    TokenStream::from(expanded)
}

/// Derive `Sealed` + `Event`. Same shape as `ArkheComponent`; the user
/// type must additionally derive `Debug` plus serde.
#[proc_macro_derive(ArkheEvent, attributes(arkhe))]
pub fn derive_arkhe_event(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident.clone();
    let args = match parse_arkhe_args(&input.attrs, &name) {
        Ok(a) => a,
        Err(ts) => return ts,
    };
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let sealed = sealed_impl(&name, &input.generics);
    let type_code = args.type_code;
    let schema_version = args.schema_version;

    let expanded = quote! {
        #sealed

        impl #impl_generics ::arkhe_kernel::state::traits::Event
            for #name #ty_generics #where_clause
        {
            const TYPE_CODE: ::arkhe_kernel::abi::TypeCode =
                ::arkhe_kernel::abi::TypeCode(#type_code);
            const SCHEMA_VERSION: u32 = #schema_version;
        }
    };

    TokenStream::from(expanded)
}
