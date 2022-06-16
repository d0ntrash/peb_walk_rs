# Dynamically resolve and invoke Windows APIs using Rust
This is a working PoC which can be used to dynamically resolve and invoke Windows APIs using Rust. This might help to avoid suspicious imports and the usage of `LoadLibrary` and `GetProcAddress`.
# TODO
* Make code less ugly and do some error handling.
* Add search by ordinal number
* Add search by hash