class Coronarium < Formula
  desc "Cross-platform supply-chain guard for every package manager"
  homepage "https://github.com/bokuweb/coronarium"
  license "MIT"
  version "0.26.0"

  # This formula is a per-release binary installer — we consume the
  # prebuilt tarballs that `.github/workflows/release.yml` publishes
  # to the GitHub Release. Keeps the formula tiny (no cargo build,
  # no nightly toolchain for the eBPF object) and lets users on
  # macOS benefit immediately.
  #
  # The `.github/workflows/homebrew-formula.yml` workflow rewrites
  # the URLs + sha256s on every `v*` tag push, so the only manual
  # step is the initial tap setup.

  on_macos do
    on_arm do
      url "https://github.com/bokuweb/coronarium/releases/download/v0.26.0/coronarium-aarch64-apple-darwin.tar.gz"
      sha256 "80907949dc623686245be77c5833fba3d41a3b8d66406d2ea4c10fa0f1793251"
    end
    on_intel do
      url "https://github.com/bokuweb/coronarium/releases/download/v0.26.0/coronarium-x86_64-apple-darwin.tar.gz"
      sha256 "f6d2c6e8770eb70a7b2173aa10043f28215e9a655db5fc0a80c9aef00fdf17c8"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/bokuweb/coronarium/releases/download/v0.26.0/coronarium-aarch64-unknown-linux-musl.tar.gz"
      sha256 "7ae6f9a1e7f9ad369b80571eebb00ca64692598d0bc1c1df11d84ad07c828b57"
    end
    on_intel do
      url "https://github.com/bokuweb/coronarium/releases/download/v0.26.0/coronarium-x86_64-unknown-linux-musl.tar.gz"
      sha256 "ba9bf9f8a7dbe8b21daf3e0ce72c29873dc56ea4eac6716f3a92ce19c234986e"
    end
  end

  def install
    bin.install "coronarium"
    # Linux tarball also ships the eBPF object — only useful for
    # `coronarium run` supervised mode. Install it next to the binary
    # so the default `CORONARIUM_BPF_OBJ` search path finds it.
    if OS.linux?
      (libexec/"bpf").install "coronarium.bpf.o" if File.exist?("coronarium.bpf.o")
    end
  end

  def caveats
    <<~EOS
      coronarium is installed. Desktop quick start (three commands):

        coronarium proxy install-ca        # trust the proxy's root CA
        coronarium proxy install-daemon    # run the proxy in the background
        coronarium install-gate install    # route your shell through it

      Open a new shell, then `npm install` / `cargo add` / `pip install` will
      silently fall back to versions older than --min-age (default 7d).

      Verify the install:

        coronarium doctor

      #{OS.linux? ? "eBPF supervised-run mode (`coronarium run`) needs the bpf object at:\n  #{libexec}/bpf/coronarium.bpf.o\nExport CORONARIUM_BPF_OBJ=$(brew --prefix)/opt/coronarium/libexec/bpf/coronarium.bpf.o\nbefore running `coronarium run`." : ""}
    EOS
  end

  test do
    # Smoke the binary starts and reports its version.
    assert_match version.to_s, shell_output("#{bin}/coronarium --version")
    # Policy parser exits cleanly on a minimal document.
    (testpath/"policy.yml").write <<~YAML
      mode: audit
      network:
        default: allow
      file:
        default: allow
    YAML
    system "#{bin}/coronarium", "check-policy", "-p", testpath/"policy.yml"
  end
end
