# coronarium on macOS

A resident-watch mode that monitors lockfiles in your workspace and
pops a macOS notification whenever a new dependency is too young to
trust. Works across npm, cargo, pypi, and nuget.

## Install

```bash
brew install --no-quarantine bokuweb/tap/coronarium   # once that tap exists
# or, for now:
curl -fsSL https://github.com/bokuweb/coronarium/releases/latest/download/coronarium-aarch64-apple-darwin.tar.gz \
  | tar -xz -C /tmp \
  && sudo mv /tmp/coronarium-aarch64-apple-darwin/coronarium /usr/local/bin/
```

## Run it once (no daemon)

```bash
coronarium deps watch --min-age 7d ~/code
```

Leave it running in a tmux window. Every lockfile rewrite in
`~/code/**/{package-lock.json,Cargo.lock,uv.lock,poetry.lock,requirements.txt,packages.lock.json}`
triggers a check; violations pop a macOS notification.

## Run it at login (launchd)

1. Copy and edit the plist:

   ```bash
   cp packaging/macos/dev.coronarium.watch.plist ~/Library/LaunchAgents/
   # Edit the ProgramArguments paths to match your setup.
   ```

2. Load it:

   ```bash
   launchctl load ~/Library/LaunchAgents/dev.coronarium.watch.plist
   launchctl start dev.coronarium.watch
   ```

3. Verify:

   ```bash
   launchctl list | grep coronarium
   tail -f /tmp/coronarium-watch.log
   ```

4. Unload when you're done:

   ```bash
   launchctl unload ~/Library/LaunchAgents/dev.coronarium.watch.plist
   ```

## Notification permissions

The first time `coronarium` posts a notification, macOS asks whether
to allow "Script Editor" (osascript's signed bundle) to deliver
notifications. Click **Allow**. You can later revoke / tweak the
setting in *System Settings → Notifications → Script Editor*.
