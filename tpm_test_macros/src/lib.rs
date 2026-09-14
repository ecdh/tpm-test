use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{
    parse_macro_input, Expr, ExprArray, ExprLit, ItemFn, Lit, Meta, MetaNameValue, ReturnType,
    Token,
};

#[derive(Default, Debug, PartialEq, Eq)]
struct TpmTestArgs {
    name: Option<String>,
    description: Option<String>,
    categories: Vec<String>,
    hierarchies: Vec<String>,
    sim_only: bool,
}

impl Parse for TpmTestArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut args = TpmTestArgs::default();
        let nested = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;

        for meta in nested {
            match meta {
                Meta::Path(path) if path.is_ident("sim_only") => {
                    args.sim_only = true;
                }
                Meta::NameValue(MetaNameValue { path, value, .. }) => {
                    let key = path.get_ident().map(|i| i.to_string()).unwrap_or_default();
                    match key.as_str() {
                        "name" => {
                            args.name = Some(extract_str_lit(
                                &value,
                                "Expected string literal for `name`",
                            )?);
                        }
                        "description" => {
                            args.description = Some(extract_str_lit(
                                &value,
                                "Expected string literal for `description`",
                            )?);
                        }
                        "category" | "categories" => {
                            extract_string_list(&value, &mut args.categories)?;
                        }
                        "hierarchy" | "hierarchies" => {
                            extract_string_list(&value, &mut args.hierarchies)?;
                        }
                        "sim_only" => {
                            if let Expr::Lit(ExprLit {
                                lit: Lit::Bool(b), ..
                            }) = &value
                            {
                                args.sim_only = b.value();
                            } else {
                                return Err(syn::Error::new_spanned(
                                    &value,
                                    "Expected boolean literal for `sim_only`",
                                ));
                            }
                        }
                        other => {
                            return Err(syn::Error::new_spanned(
                                path,
                                format!("Unknown argument `{}` for tpm_test attribute", other),
                            ));
                        }
                    }
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        other,
                        "Expected key = value format in tpm_test attribute",
                    ));
                }
            }
        }

        Ok(args)
    }
}

/// Extracts a Rust string literal from `expr`, or returns a compile-time `syn::Error` with `err_msg`.
fn extract_str_lit(expr: &Expr, err_msg: &str) -> syn::Result<String> {
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(s), ..
    }) = expr
    {
        Ok(s.value())
    } else {
        Err(syn::Error::new_spanned(expr, err_msg))
    }
}

/// Trims whitespace from `val` and appends it to `out` if non-empty.
fn push_non_empty(val: &str, out: &mut Vec<String>) {
    let trimmed = val.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
}

/// Parses a string literal (delimited by `|` or `,`) or an array of string literals into `out`.
fn extract_string_list(expr: &Expr, out: &mut Vec<String>) -> syn::Result<()> {
    match expr {
        Expr::Lit(_) => {
            let s = extract_str_lit(expr, "Expected string literal")?;
            for part in s.split(['|', ',']) {
                push_non_empty(part, out);
            }
            Ok(())
        }
        Expr::Array(ExprArray { elems, .. }) => {
            for elem in elems {
                let s = extract_str_lit(elem, "Expected string literal in array")?;
                push_non_empty(&s, out);
            }
            Ok(())
        }
        _ => Err(syn::Error::new_spanned(
            expr,
            "Expected string literal or array of string literals",
        )),
    }
}

/// Generates a token expression evaluating to `BitFlags<#type_path>`, using `#type_path::#default_fn()`
/// when `items` is empty or OR-ing each item via `#parse_fn` when `items` is non-empty.
fn expand_bitflags_expr(
    items: &[String],
    test_name: &str,
    type_path: TokenStream2,
    default_fn: TokenStream2,
    parse_fn: TokenStream2,
    kind: &str,
) -> TokenStream2 {
    if items.is_empty() {
        quote! { #type_path::#default_fn() }
    } else {
        quote! {{
            let mut __flags = ::tpm_test_support::BitFlags::<#type_path>::empty();
            #(
                match #parse_fn(#items) {
                    Some(__flag) => __flags |= __flag,
                    None => panic!(
                        "Unknown test {} `{}` specified on test `{}`",
                        #kind, #items, #test_name
                    ),
                }
            )*
            __flags
        }}
    }
}

fn expand_tpm_test(args: TpmTestArgs, input_fn: ItemFn) -> TokenStream2 {
    let fn_vis = &input_fn.vis;
    let fn_sig = &input_fn.sig;
    let fn_ident = &input_fn.sig.ident;
    let fn_stmts = &input_fn.block.stmts;
    let fn_attrs = &input_fn.attrs;

    let test_name = args.name.unwrap_or_else(|| fn_ident.to_string());
    let description = args.description.unwrap_or_default();
    let sim_only = args.sim_only;

    let categories_expr = expand_bitflags_expr(
        &args.categories,
        &test_name,
        quote!(::tpm_test_support::TestCategory),
        quote!(default_categories),
        quote!(::tpm_test_support::parse_category),
        "category",
    );

    let hierarchies_expr = expand_bitflags_expr(
        &args.hierarchies,
        &test_name,
        quote!(::tpm_test_support::TestHierarchy),
        quote!(default_hierarchies),
        quote!(::tpm_test_support::parse_hierarchy),
        "hierarchy",
    );

    let early_return = match &fn_sig.output {
        ReturnType::Default => quote! { return; },
        ReturnType::Type(_, _) => quote! { return Ok(()); },
    };

    let has_test_attr = fn_attrs.iter().any(|attr| attr.path().is_ident("test"));
    let test_attr = if fn_ident == "main" || has_test_attr {
        quote! {}
    } else {
        quote! { #[test] }
    };

    quote! {
        #test_attr
        #(#fn_attrs)*
        #fn_vis #fn_sig {
            let _ = ::tpm_test_support::env_logger::Builder::from_env(
                ::tpm_test_support::env_logger::Env::default().default_filter_or("info")
            ).is_test(true).try_init();

            let __metadata = ::tpm_test_support::TestCaseMetadata {
                name: #test_name,
                description: #description,
                categories: #categories_expr,
                hierarchies: #hierarchies_expr,
                sim_only: #sim_only,
            };

            if !__metadata.should_run() {
                #early_return
            }

            #(#fn_stmts)*
        }
    }
}

/// Marks a test case and injects TCG test metadata, logging initialization, and execution filter guards.
///
/// # Usage
/// ```rust,ignore
/// #[tpm_test(
///     categories = "Compliance | Pcr | Smoke",
///     hierarchies = "Null",
///     description = "Test PCR extend and read"
/// )]
/// fn test_pcr() {
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn tpm_test(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as TpmTestArgs);
    let input_fn = parse_macro_input!(item as ItemFn);
    TokenStream::from(expand_tpm_test(args, input_fn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_str;

    #[test]
    fn test_parse_empty_args() {
        let args: TpmTestArgs = parse_str("").unwrap();
        assert!(args.name.is_none());
        assert!(args.description.is_none());
        assert!(args.categories.is_empty());
        assert!(args.hierarchies.is_empty());
    }

    #[test]
    fn test_parse_string_list_and_pipe() {
        let args: TpmTestArgs =
            parse_str(r#"categories = "Compliance | Pcr | Smoke", hierarchies = "Null, Owner""#)
                .unwrap();
        assert_eq!(args.categories, vec!["Compliance", "Pcr", "Smoke"]);
        assert_eq!(args.hierarchies, vec!["Null", "Owner"]);
    }

    #[test]
    fn test_parse_array_syntax() {
        let args: TpmTestArgs =
            parse_str(r#"categories = ["Compliance", "", "Smoke", "  "], hierarchies = ["Null"]"#)
                .unwrap();
        assert_eq!(args.categories, vec!["Compliance", "Smoke"]);
        assert_eq!(args.hierarchies, vec!["Null"]);
    }

    #[test]
    fn test_parse_name_and_description() {
        let args: TpmTestArgs =
            parse_str(r#"name = "custom_test", description = "A descriptive test purpose""#)
                .unwrap();
        assert_eq!(args.name, Some("custom_test".to_string()));
        assert_eq!(
            args.description,
            Some("A descriptive test purpose".to_string())
        );
    }

    #[test]
    fn test_parse_non_string_name_error() {
        let err = parse_str::<TpmTestArgs>(r#"name = 123"#).unwrap_err();
        assert!(err
            .to_string()
            .contains("Expected string literal for `name`"));
    }

    #[test]
    fn test_parse_non_string_description_error() {
        let err = parse_str::<TpmTestArgs>(r#"description = true"#).unwrap_err();
        assert!(err
            .to_string()
            .contains("Expected string literal for `description`"));
    }

    #[test]
    fn test_parse_array_non_string_element_error() {
        let err = parse_str::<TpmTestArgs>(r#"categories = [123]"#).unwrap_err();
        assert!(err.to_string().contains("Expected string literal in array"));
    }

    #[test]
    fn test_parse_unknown_arg_error() {
        let err = parse_str::<TpmTestArgs>(r#"unknown_key = "value""#).unwrap_err();
        assert!(err.to_string().contains("Unknown argument `unknown_key`"));
    }

    #[test]
    fn test_expand_defaults() {
        let args: TpmTestArgs = parse_str("").unwrap();
        let input_fn: ItemFn = parse_str("fn my_test() { let x = 42; }").unwrap();
        let expanded = expand_tpm_test(args, input_fn).to_string();
        assert!(expanded.contains("# [test]"));
        assert!(expanded.contains("fn my_test ()"));
        assert!(expanded.contains("default_categories"));
        assert!(expanded.contains("default_hierarchies"));
        assert!(expanded.contains("return ;"));
        assert!(expanded.contains("let x = 42 ;"));
    }

    #[test]
    fn test_expand_explicit_categories_and_hierarchies() {
        let args: TpmTestArgs =
            parse_str(r#"categories = "Compliance | Pcr", hierarchies = "Owner""#).unwrap();
        let input_fn: ItemFn = parse_str("fn my_test() {}").unwrap();
        let expanded = expand_tpm_test(args, input_fn).to_string();
        assert!(expanded.contains("parse_category"));
        assert!(expanded.contains("Compliance"));
        assert!(expanded.contains("Pcr"));
        assert!(expanded.contains("parse_hierarchy"));
        assert!(expanded.contains("Owner"));
    }

    #[test]
    fn test_expand_result_return() {
        let args: TpmTestArgs = parse_str("").unwrap();
        let input_fn: ItemFn = parse_str("fn my_test() -> Result<()> { Ok(()) }").unwrap();
        let expanded = expand_tpm_test(args, input_fn).to_string();
        assert!(expanded.contains("return Ok (()) ;"));
    }

    #[test]
    fn test_expand_main_fn_no_test_attr() {
        let args: TpmTestArgs = parse_str("").unwrap();
        let input_fn: ItemFn = parse_str("fn main() {}").unwrap();
        let expanded = expand_tpm_test(args, input_fn).to_string();
        assert!(!expanded.contains("# [test]"));
    }

    #[test]
    fn test_expand_existing_test_attr_not_duplicated() {
        let args: TpmTestArgs = parse_str("").unwrap();
        let input_fn: ItemFn = parse_str("#[test] fn my_test() {}").unwrap();
        let expanded = expand_tpm_test(args, input_fn).to_string();
        // Count occurrences of #[test]
        let matches: Vec<_> = expanded.match_indices("# [test]").collect();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_expand_preserves_other_attributes() {
        let args: TpmTestArgs = parse_str("").unwrap();
        let input_fn: ItemFn = parse_str("#[should_panic] #[ignore] fn my_test() {}").unwrap();
        let expanded = expand_tpm_test(args, input_fn).to_string();
        assert!(expanded.contains("# [test]"));
        assert!(expanded.contains("# [should_panic]"));
        assert!(expanded.contains("# [ignore]"));
    }

    #[test]
    fn test_parse_and_expand_sim_only() {
        let args_kv: TpmTestArgs = parse_str("sim_only = true").unwrap();
        assert!(args_kv.sim_only);

        let args_flag: TpmTestArgs = parse_str("sim_only").unwrap();
        assert!(args_flag.sim_only);

        let input_fn: ItemFn = parse_str("fn my_sim_test() {}").unwrap();
        let expanded = expand_tpm_test(args_kv, input_fn).to_string();
        assert!(expanded.contains("sim_only : true"));
    }
}
