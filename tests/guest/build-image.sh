#!/usr/bin/env bash
# Build the Solstice test guest: a stateless Alpine initramfs with X, the QXL
# driver, spice-vdagent and the QEMU guest agent.
#
# Runs entirely unprivileged. `unshare -Ur` supplies a user namespace in which
# apk can chown to root, so there is no sudo anywhere in this script and no
# installer is ever booted -- the rootfs is assembled on the host and packed.
#
#   ./tests/guest/build-image.sh                # build if stale, else nothing
#   ./tests/guest/build-image.sh --force        # rebuild unconditionally
#   ./tests/guest/build-image.sh --update-lock  # rebuild and accept new versions
#
# Output lands in $SOLSTICE_GUEST_DIR, or ~/.cache/solstice/guest by default:
#   vmlinuz         the linux-virt kernel, booted directly (no bootloader)
#   initramfs.gz    the entire guest, unpacked into RAM at boot
#   manifest.lock   resolved package versions; compared against the committed
#                   copy in tests/guest/ so a stale image is loud, not silent
set -euo pipefail

BRANCH=v3.24
ARCH=x86_64
MIRROR=${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT=${SOLSTICE_GUEST_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/solstice/guest}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/solstice-guest.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

force=0 update_lock=0
for a in "$@"; do
    case $a in
        --force)       force=1 ;;
        --update-lock) update_lock=1; force=1 ;;
        *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*" >&2; }

for t in curl unshare cpio gzip tar; do
    command -v "$t" >/dev/null || { echo "missing required tool: $t" >&2; exit 1; }
done
unshare -Ur true 2>/dev/null || {
    echo "unprivileged user namespaces are unavailable; this script needs them" >&2
    exit 1
}

if [[ $force -eq 0 && -f $OUT/manifest.lock && -f $HERE/manifest.lock ]] \
   && cmp -s "$OUT/manifest.lock" "$HERE/manifest.lock" \
   && [[ -f $OUT/vmlinuz && -f $OUT/initramfs.gz ]]; then
    say "guest image is current ($OUT)"; exit 0
fi

# --- bootstrap apk and the signing keys ---------------------------------
say "fetching apk-tools-static and alpine-keys from $BRANCH"
index() { curl -sfL "$MIRROR/$BRANCH/main/$ARCH/" | grep -oE "$1-[0-9][^\"<]*\.apk" | head -1; }
APK_PKG=$(index apk-tools-static); KEYS_PKG=$(index alpine-keys)
[[ -n $APK_PKG && -n $KEYS_PKG ]] || { echo "could not resolve bootstrap packages" >&2; exit 1; }

mkdir -p "$WORK/apk" "$WORK/keys"
curl -sfL "$MIRROR/$BRANCH/main/$ARCH/$APK_PKG"  | tar -xz -C "$WORK/apk"  2>/dev/null
curl -sfL "$MIRROR/$BRANCH/main/$ARCH/$KEYS_PKG" | tar -xz -C "$WORK/keys" 2>/dev/null
APK=$WORK/apk/sbin/apk.static
[[ -x $APK ]] || { echo "apk.static not found in $APK_PKG" >&2; exit 1; }

# --- assemble the rootfs ------------------------------------------------
ROOT=$WORK/root
mkdir -p "$ROOT/etc/apk/keys"
cp "$WORK"/keys/etc/apk/keys/* "$ROOT/etc/apk/keys/"
printf '%s\n%s\n' "$MIRROR/$BRANCH/main" "$MIRROR/$BRANCH/community" > "$WORK/repos"
mapfile -t PKGS < <(grep -vE '^\s*(#|$)' "$HERE/packages")
mapfile -t BUILD_PKGS < <(grep -vE '^\s*(#|$)' "$HERE/packages.build")

say "installing ${#PKGS[@]} runtime and ${#BUILD_PKGS[@]} build packages"
PKGS+=("${BUILD_PKGS[@]}")
unshare -Ur "$APK" --root "$ROOT" --initdb --arch "$ARCH" \
    --repositories-file "$WORK/repos" --no-cache add "${PKGS[@]}" >"$WORK/apk.log" 2>&1 \
    || { tail -30 "$WORK/apk.log" >&2; echo "apk failed; see above" >&2; exit 1; }
tail -1 "$WORK/apk.log" >&2

install -D -m 0755 "$HERE/init"       "$ROOT/init"
install -D -m 0644 "$HERE/xorg.conf"  "$ROOT/etc/X11/xorg.conf"

# The draw helper paints the guest from the test harness (see its header for
# what it does and does not reach). Same architecture as the host, so it
# compiles in a plain chroot -- no cross toolchain, no first-boot build step.
if [[ -f $HERE/draw-helper.c ]]; then
    say "compiling the draw helper in the guest toolchain"
    install -D -m 0644 "$HERE/draw-helper.c" "$ROOT/tmp/draw-helper.c"
    unshare -Ur --mount sh -c "
        mount -t proc proc '$ROOT/proc' 2>/dev/null
        chroot '$ROOT' /usr/bin/gcc -O1 -Wall -o /usr/local/bin/solstice-draw \
            /tmp/draw-helper.c -lX11 -lXext" >>"$WORK/apk.log" 2>&1 \
        || { tail -20 "$WORK/apk.log" >&2; exit 1; }
    rm -f "$ROOT/tmp/draw-helper.c"

    say "removing the build toolchain again"
    unshare -Ur "$APK" --root "$ROOT" --no-cache del "${BUILD_PKGS[@]}" \
        >>"$WORK/apk.log" 2>&1 || { tail -20 "$WORK/apk.log" >&2; exit 1; }
fi

# The kernel boots from outside the archive, so take it out rather than ship
# it twice; same for Alpine's own initramfs, which this image replaces.
mkdir -p "$OUT"
cp "$ROOT/boot/vmlinuz-virt" "$WORK/vmlinuz"
KVER=$(basename "$(find "$ROOT/lib/modules" -maxdepth 1 -mindepth 1 -type d | head -1)")
rm -f "$ROOT/boot/initramfs-virt" "$ROOT/boot/vmlinuz-virt" "$ROOT/boot/System.map-$KVER"

# --- pack -----------------------------------------------------------------
say "packing the initramfs (kernel $KVER)"
unshare -Ur sh -c "cd '$ROOT' && find . -print0 | LC_ALL=C sort -z \
    | cpio --null --create --format=newc --quiet" > "$WORK/initramfs.cpio"
gzip -9 -n -c "$WORK/initramfs.cpio" > "$WORK/initramfs.gz"

{
    echo "# Generated by tests/guest/build-image.sh -- commit this file."
    echo "# A mismatch against the built image means the guest is stale."
    echo "alpine-branch $BRANCH"
    echo "arch          $ARCH"
    echo "kernel        $KVER"
    echo "bootstrap     $APK_PKG $KEYS_PKG"
    # The files this script installs from tests/guest, so that changing one
    # makes a cached image stale rather than silently keeping the old copy.
    for f in init xorg.conf draw-helper.c; do
        if [[ -f $HERE/$f ]]; then
            printf 'input         %s %s\n' "$f" "$(sha256sum < "$HERE/$f" | cut -c1-16)"
        fi
    done
    echo "---"
    unshare -Ur "$APK" --root "$ROOT" list --installed 2>/dev/null \
        | awk '{print $1}' | LC_ALL=C sort
} > "$WORK/manifest.lock"

mv "$WORK/vmlinuz" "$WORK/initramfs.gz" "$WORK/manifest.lock" "$OUT/"

# Alpine's repositories move under a fixed branch, so the same inputs resolve
# to different package versions on different days. Treat that as something to
# look at rather than something to absorb silently: the committed lock is only
# rewritten when asked for explicitly.
if [[ ! -f $HERE/manifest.lock ]] || [[ $update_lock -eq 1 ]]; then
    cp "$OUT/manifest.lock" "$HERE/manifest.lock"
    say "wrote tests/guest/manifest.lock"
elif ! cmp -s "$OUT/manifest.lock" "$HERE/manifest.lock"; then
    say "WARNING: upstream has moved since the lock was written:"
    diff -u "$HERE/manifest.lock" "$OUT/manifest.lock" | grep -E '^[-+][a-z]' | head -20 >&2
    say "the built image is usable; re-run with --update-lock to accept it"
fi

say "built $OUT"
ls -lh "$OUT" | tail -n +2 >&2
