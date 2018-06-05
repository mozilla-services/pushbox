# Documentation and `cargo doc` -- a guide

A few things to note:

1) Read the [RustDoc
book](https://doc.rust-lang.org/rustdoc/index.html). It's short and
full of useful information. It also leaves out a few things.

2) By default, `rustdoc` will look for either `main.rs` or `lib.rs` as
a starting point for documents.

3) It's normative to have each file start with a `//!` block
descriptor. For example:

```rust
#![feature(...)]
#![plugin(...)]

//! HappyFunProgram: A super happy fun program you should not taunt.
//!
//! The super happy fun program contains less than the federally
//! specified minimum of radioactive toxins and should only be enjoyed
//! with adult supervision and proper eye and clothing protection.

#[macro_use]
extern crate plutonium
...

pub mod games; // this will be documented
mod toxins; // this will NOT be documented

```

4) Only items marked as `pub` will be documented by `rustdoc`. This
includes `mod` inclusions in main or lib, which may direct which
modules or files are included in the output.

