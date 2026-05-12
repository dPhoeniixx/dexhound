# dexhound

<p align="center">
  <img src="mascot.jpg" alt="dexhound mascot" width="420">
</p>

Dump DEX files out of a running Android process — no instrumentation, no injection, no hooks.

## Why

On a rooted device with Magisk + DenyList, most RASP-protected apps run fine. But some still detect instrumentation tools like **Frida**, which makes the usual "attach and dump classloaders" approach fail.

`dexhound` doesn't attach to the process. It just reads memory through `/proc/<pid>/mem` and carves out anything that looks like a DEX. The target app sees nothing.

## How it works

1. Resolve the target (PID or package name via `/proc/*/cmdline`).
2. Walk `/proc/<pid>/maps`, skip system/framework/other-app regions.
3. Read each readable region from `/proc/<pid>/mem`.
4. Scan for the DEX magic (`dex\n0XX\0`), validate header size + endian tag + file size.
5. Verify Adler-32; tag the dump `OK` or `MISMATCH`.
6. Write each hit to `<outdir>/dump_<addr>_<tag>.dex`.

## Build

Cross-compile from any host using the Android NDK. Point `NDK` at your install (Android Studio puts it under `~/Library/Android/sdk/ndk/<version>` on macOS) and run:

```sh
TC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin   # or linux-x86_64
mkdir -p build
$TC/aarch64-linux-android30-clang   dexhound.c -O2 -s -o build/dexhound-arm64-v8a
$TC/armv7a-linux-androideabi30-clang dexhound.c -O2 -s -o build/dexhound-armeabi-v7a
$TC/x86_64-linux-android30-clang    dexhound.c -O2 -s -o build/dexhound-x86_64
$TC/i686-linux-android30-clang      dexhound.c -O2 -s -o build/dexhound-x86
```

Push the matching binary to the device and run it as root.

## Usage

```
./dexhound <pid|package> <outdir>
```

Examples:

```
./dexhound com.example.app /data/local/tmp/out
./dexhound 12345         /data/local/tmp/out
```

### Running against a RASP-protected app

If the target app uses RASP and refuses to launch on a rooted device, the cleanest setup is:

1. Install **Magisk** and enable **Zygisk**.
2. Open Magisk → **Configure DenyList** → tick the target package.
3. Launch the app — it sees a "clean" environment and runs normally.
4. While it's running, dump it from another shell:

   ```
   su -c '/data/local/tmp/dexhound com.example.app /data/local/tmp/out'
   ```

Because dexhound never attaches, injects, or loads anything into the target, RASP checks (Frida detection, ptrace probes, hook scans, etc.) don't fire — DenyList alone is enough to get past the boot-time root check.

## Requirements

- Rooted Android device (needs read access to `/proc/<pid>/mem`).
- Target process already running.
- Any Android ABI — `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`.
