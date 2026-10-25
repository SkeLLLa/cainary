#!/bin/sh
# The APT and DNF repositories that release.yml's `pages` job publishes on GitHub Pages, the same
# layout as SkeLLLa/plasma-drop's: deb/ with suite stable, component main, and rpm/$basearch/.
# Pages replaces the site on every deploy, so ASSETS holds every version the site keeps: this
# release's packages plus those the job fetched from recent releases.
#
# Usage:
#   packaging/ci/pages-repo.sh ASSETS OUT BASE_URL VERSION
#       ASSETS    cainary_*_{amd64,arm64}.deb and cainary-*-1.{x86_64,aarch64}.rpm files;
#                 those of VERSION must be among them
#       OUT       the site directory to create (must not exist)
#       BASE_URL  where OUT is served, e.g. https://skellla.github.io/cainary
#
# Needs apt-ftparchive (apt-utils) and createrepo_c. When gpg holds a secret key (exactly one),
# it signs the APT Release file, each .rpm and each repomd.xml, and the repository files check
# them; otherwise the repositories are unsigned, as plasma-drop's are ([trusted=yes],
# repo_gpgcheck=0). Signing the .rpm files needs rpmsign and rpmkeys: the release's own are
# already signed and stay byte-identical, and those of releases from before the key are signed
# here. release.yml checks the key against packaging/signing/repo.asc before this runs.
set -eu

die() {
    echo "error: $*" >&2
    exit 1
}

[ "$#" -eq 4 ] || die "usage: $0 ASSETS OUT BASE_URL VERSION"
assets=$1
out=$2
base_url=${3%/}
version=$4
[ -d "$assets" ] || die "$assets is not a directory"
[ ! -e "$out" ] || die "$out already exists"
case "$base_url" in https://* | file:///*) ;; *) die "BASE_URL must be https:// or file:///" ;; esac

for tool in apt-ftparchive createrepo_c; do
    command -v "$tool" > /dev/null || die "$tool is not installed"
done

key=
if command -v gpg > /dev/null; then
    keys="$(gpg --batch --with-colons --list-secret-keys 2> /dev/null | grep -c '^sec:' || true)"
    case "$keys" in
        0) ;;
        1) key="$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')" ;;
        *) die "gpg holds $keys secret keys; the signing key must be the only one" ;;
    esac
fi
sign() {
    gpg --batch --yes --pinentry-mode loopback --local-user "$key" "$@"
}
if [ -n "$key" ]; then
    for tool in rpmsign rpmkeys; do
        command -v "$tool" > /dev/null || die "$tool is not installed (needed to sign the .rpm files)"
    done
fi

for f in "cainary_${version}_amd64.deb" "cainary_${version}_arm64.deb" \
    "cainary-${version}-1.x86_64.rpm" "cainary-${version}-1.aarch64.rpm"; do
    [ -f "$assets/$f" ] || die "$assets/$f is missing"
done

mkdir -p "$out"
[ -z "$key" ] || gpg --batch --armor --export "$key" > "$out/cainary.asc"

# --- APT: one suite, stable, with the main component ---------------------------------------
deb="$out/deb"
mkdir -p "$deb/pool/main/c/cainary"
cp "$assets"/cainary_*_amd64.deb "$assets"/cainary_*_arm64.deb "$deb/pool/main/c/cainary/"
(
    cd "$deb"
    for arch in amd64 arm64; do
        dir="dists/stable/main/binary-$arch"
        mkdir -p "$dir"
        apt-ftparchive --arch "$arch" packages pool > "$dir/Packages"
        grep -q "^Version: $version\$" "$dir/Packages" || die "no $version package in $dir/Packages"
        gzip -9n < "$dir/Packages" > "$dir/Packages.gz"
    done
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=cAInary \
        -o APT::FTPArchive::Release::Label=cAInary \
        -o APT::FTPArchive::Release::Suite=stable \
        -o APT::FTPArchive::Release::Codename=stable \
        -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
        -o APT::FTPArchive::Release::Components=main \
        -o APT::FTPArchive::Release::Description="cAInary APT repository" \
        release dists/stable > Release.tmp
    mv Release.tmp dists/stable/Release
    if [ -n "$key" ]; then
        sign --clearsign --output dists/stable/InRelease dists/stable/Release
        sign --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
    fi
)
if [ -n "$key" ]; then
    deb_line="deb [signed-by=/etc/apt/keyrings/cainary.asc] $base_url/deb stable main"
else
    deb_line="deb [trusted=yes] $base_url/deb stable main"
fi
echo "$deb_line" > "$deb/cainary.list"

# --- DNF: one repository per architecture, rpm/$basearch -----------------------------------
for arch in x86_64 aarch64; do
    dir="$out/rpm/$arch"
    mkdir -p "$dir"
    cp "$assets"/cainary-*-1."$arch".rpm "$dir/"
    if [ -n "$key" ]; then
        # __gpg: Debian's rpm looks for gpg2. An identical signature is left as it is.
        rpmsign --define "__gpg $(command -v gpg)" --define "_gpg_name $key" \
            --define "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback" \
            --addsign "$dir"/*.rpm > /dev/null
        db="$(mktemp -d)"
        rpmkeys --dbpath "$db" --import "$out/cainary.asc"
        for f in "$dir"/*.rpm; do
            rpmkeys --dbpath "$db" --define '_pkgverify_level signature' --checksig "$f" > /dev/null ||
                die "$f did not verify after signing"
        done
        rm -rf "$db"
    fi
    createrepo_c --quiet --compatibility "$dir"
    [ -z "$key" ] || sign --armor --detach-sign --output "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml"
done
if [ -n "$key" ]; then
    rpm_check="gpgcheck=1
repo_gpgcheck=1
gpgkey=$base_url/cainary.asc"
else
    rpm_check="gpgcheck=0
repo_gpgcheck=0"
fi
cat > "$out/rpm/cainary.repo" << EOF
[cainary]
name=cAInary
baseurl=$base_url/rpm/\$basearch
enabled=1
$rpm_check
EOF

# --- The landing page ---------------------------------------------------------------------
if [ -n "$key" ]; then
    apt_setup="sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/cainary.asc $base_url/cainary.asc
"
    trust="The packages and the repository metadata are signed with <a href=\"cainary.asc\">cainary.asc</a>
(fingerprint <code>$key</code>)."
else
    apt_setup=
    trust="These repositories are unsigned."
fi
cat > "$out/index.html" << EOF
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>cAInary package repositories</title>
  </head>
  <body>
    <h1>cAInary package repositories</h1>
    <p>The tray app and CLI from <a href="https://github.com/SkeLLLa/cainary">SkeLLLa/cainary</a>,
    latest $version. $trust GitHub Releases remain the long-term artifact archive.</p>
    <h2>RPM / DNF (Fedora 44+)</h2>
    <pre>sudo curl -fsSLo /etc/yum.repos.d/cainary.repo $base_url/rpm/cainary.repo
sudo dnf install cainary</pre>
    <h2>APT (Debian 13+, Ubuntu 25.04+)</h2>
    <pre>${apt_setup}echo '$deb_line' | sudo tee /etc/apt/sources.list.d/cainary.list
sudo apt update
sudo apt install cainary</pre>
  </body>
</html>
EOF
touch "$out/.nojekyll"

set -- "$deb"/pool/main/c/cainary/*.deb
echo "wrote $out for cainary $version ($# .deb files), ${key:+signed by }${key:-unsigned}"
