alias bk := build_ksud
alias bm := build_manager
alias bi := build_ksuinit

build_ksuinit:
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang" \
    RUSTFLAGS="-C link-arg=-no-pie" \
    cargo build --target=aarch64-unknown-linux-musl --release --manifest-path ./userspace/ksuinit/Cargo.toml
    cp userspace/ksuinit/target/aarch64-unknown-linux-musl/release/ksuinit userspace/ksud/bin/aarch64/ksuinit
    mkdir -p manager/app/src/main/jniLibs/arm64-v8a
    cp userspace/ksuinit/target/aarch64-unknown-linux-musl/release/ksuinit manager/app/src/main/jniLibs/arm64-v8a/libksuinit.so

build_ksud:
    cross build --target aarch64-linux-android --release --manifest-path ./userspace/ksud/Cargo.toml

build_manager: build_ksud
    mkdir -p manager/app/src/main/jniLibs/arm64-v8a
    cp userspace/ksud/target/aarch64-linux-android/release/ksud manager/app/src/main/jniLibs/arm64-v8a/libksud.so
    cd manager && ./gradlew aDebug

clippy:
    cargo fmt --manifest-path ./userspace/ksud/Cargo.toml
    cross clippy --target x86_64-pc-windows-gnu --release --manifest-path ./userspace/ksud/Cargo.toml
    cross clippy --target aarch64-linux-android --release --manifest-path ./userspace/ksud/Cargo.toml
