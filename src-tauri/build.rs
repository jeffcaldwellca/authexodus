fn main() {
    // `tauri::generate_context!` refuses to compile when `frontendDist` is missing, which would
    // make a plain `cargo test --workspace` fail in a fresh checkout or worktree before the UI
    // has ever been built. Put a placeholder there; `pnpm -C ui build` (run by
    // `beforeBuildCommand`) replaces it with the real UI. `ui/dist` is git-ignored.
    println!("cargo:rerun-if-changed=../ui/dist/index.html");
    let dist = std::path::Path::new("../ui/dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(dist).expect("create ui/dist");
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><title>authexodus</title><p>UI not built. Run pnpm -C ui build.</p>",
        )
        .expect("write placeholder index.html");
    }
    tauri_build::build()
}
