//! Host program: load the guest module and hand it both the regular preview1
//! WASI imports (so it can print) and the wasi-crypto imports (so it can do
//! cryptography on the host). The crypto functions are wired into the linker
//! exactly like WASI's own — see `wasmtime_wasi_crypto::add_to_linker`.

use wasmtime::{Engine, Linker, Module, Result, Store};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi_crypto::WasiCryptoCtx;

/// Everything the store hands out to host functions: the WASI preview1 context
/// and the wasi-crypto context, side by side.
struct Host {
    wasi: WasiP1Ctx,
    crypto: WasiCryptoCtx,
}

fn main() -> Result<()> {
    let wasm_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "examples/guest/target/wasm32-wasip1/release/demo.wasm".to_string());

    let engine = Engine::default();
    let mut linker: Linker<Host> = Linker::new(&engine);

    // Regular WASI, so the guest's println! works.
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |h: &mut Host| &mut h.wasi)?;
    // wasi-crypto, exposed the same way.
    wasmtime_wasi_crypto::add_to_linker(&mut linker, |h: &mut Host| &mut h.crypto)?;

    let host = Host {
        wasi: WasiCtxBuilder::new()
            .inherit_stdio()
            .inherit_args()
            .build_p1(),
        crypto: WasiCryptoCtx::new(),
    };
    let mut store = Store::new(&engine, host);

    let module = Module::from_file(&engine, &wasm_path)?;
    linker.module(&mut store, "", &module)?;
    linker
        .get_default(&mut store, "")?
        .typed::<(), ()>(&store)?
        .call(&mut store, ())?;

    Ok(())
}
