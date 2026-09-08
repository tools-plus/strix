# Fork maintenance

This repository is a fork of [`usestrix/strix`](https://github.com/usestrix/strix).
It carries changes we want that upstream has not taken (or may never take), and
cuts its own releases.

## Branches

| Branch | Role | Commit directly? |
| --- | --- | --- |
| `main` | A pristine mirror of `usestrix/strix@main`. Nothing of ours ever lands here. | **No** |
| `master` | Our mainline. All our work, our releases, our tags. Default branch. | Via PR |
| `claude/*`, feature branches | Work in progress, merged into `master`. | Yes |

Keeping `main` pristine is what makes syncing cheap: it can always be
fast-forwarded from upstream, and `master` merges it like any other branch.

## Syncing from upstream

```bash
git remote add upstream https://github.com/usestrix/strix    # once
git fetch upstream

git checkout main
git merge --ff-only upstream/main        # fails loudly if main ever diverged
git push origin main

git checkout master
git merge main                           # resolve conflicts here, never on main
git push origin master
```

`--ff-only` is deliberate: if it fails, someone committed to `main`, and that
needs fixing rather than merging over.

### Why conflicts should be rare

Our diff against upstream is kept deliberately narrow:

- **New files never conflict.** Most of our work lives in new modules
  (`strix/config/subscription/`, `scripts/release_version.py`, this file).
- **`pyproject.toml` version is untouched.** Upstream bumps that line on every
  release. We do not, so it never conflicts — the release workflow stamps the
  version at build time instead (see below).
- **Edits to existing files are kept minimal** and, where possible, expressed as
  a registry entry or a new branch in a `match` rather than a rewrite.

## CI

`.github/workflows/ci.yml` runs ruff, mypy and pytest on every push and PR to
`master`. It needs no secrets. Upstream ships no CI workflow, so this is
fork-only — and it is what catches a bad upstream sync before a release tag
does.

## Sandbox image

Scans run in a Kali-based container holding the pentest toolchain: nmap, sqlmap,
nuclei, subfinder, naabu, ffuf and wapiti from Kali; httpx, katana, vulnx,
gospider, interactsh-client and govulncheck built from source; arjun, dirsearch
and wafw00f via pipx; retire, eslint, ast-grep, tree-sitter and agent-browser
via npm; Chromium for browser automation; trufflehog, gitleaks and trivy; and a
generated root CA so the in-container Caido proxy can see TLS traffic. It runs
as an unprivileged `pentester` user.

No LLM credentials ever enter it — the container gets only proxy settings and
the host UID/GID, and all inference happens in the host process. Subscription
sign-in therefore needs nothing from the image.

`.github/workflows/build-sandbox.yml` builds `containers/Dockerfile` for amd64
and arm64 and publishes `ghcr.io/tools-plus/strix-sandbox`, which
`STRIX_IMAGE` now defaults to. It needs no secrets: `GITHUB_TOKEN` with
`packages: write` authenticates to GHCR. It runs on pushes touching
`containers/**`, or on demand with an explicit tag.

Publishing our own removes the last hard dependency on upstream
infrastructure — an upstream retag or deletion of `usestrix/strix-sandbox:1.3.0`
can no longer break our scans.

> The first run must be triggered manually (**Actions → Build sandbox image →
> Run workflow**), and the package defaults to private: make it public under
> the repo's Packages settings, or scans will fail to pull it.

## Installing

Our releases are built by `build-release.yml` and attached to the GitHub
Release. Two ways in, neither needing a Go toolchain:

```bash
# Standalone binary — no Python required
curl -sSL -o strix https://github.com/tools-plus/strix/releases/download/<tag>/strix-<version>-linux-x86_64
chmod +x strix

# Or the platform wheel
pipx install https://github.com/tools-plus/strix/releases/download/<tag>/strix_agent-<pkg-version>-py3-none-manylinux_2_17_x86_64.whl
```

Installing straight from the repo works too, but **builds from source and so
needs Go 1.24+** (`scripts/tui_sidecar_hook.py` compiles the Bubble Tea
sidecar into the wheel and fails without it):

```bash
pipx install git+https://github.com/tools-plus/strix@master   # requires Go
```

That is fine for developers and wrong for users. Upstream publishes
`strix-agent` to PyPI as platform wheels only — deliberately no sdist, so
nobody ever builds it at install time. We cannot reuse that name; publishing
our own PyPI package under a fork name is the only way to get a bare
`pipx install <name>`, and is not set up today.

## Releases

Releases are tag-driven. Tag `master`, and `.github/workflows/build-release.yml`
builds binaries and wheels for all five targets and publishes a GitHub Release.

```bash
git checkout master
git tag v1.6.2-TP-20260908               # v<upstream base>-TP-<YYYYMMDD>
git push origin v1.6.2-TP-20260908
```

The tag names the upstream release we are built on plus the date we cut it, so
it can never collide with an upstream tag and always says what it is based on.

One tag yields two versions, because the tag's own spelling is not a valid
Python version:

| | Example | Where it appears |
| --- | --- | --- |
| Display version | `1.6.2-TP-20260908` | Release name, binaries, archives |
| Package version | `1.6.2+tp.20260908` | The wheel (PEP 440 local version) |

Both sort immediately after upstream `1.6.2` and before `1.6.3`.
`scripts/release_version.py` derives them; `tests/test_release_version.py` pins
the behaviour. An upstream-shaped tag (`v1.6.2`) passes through unchanged, so
the workflow stays correct if it is ever run on an upstream tag.

## Sending work upstream

**Open upstream PRs from a clean topic branch, never from `master`.**

`master` carries fork-only commits — the release-workflow change, this file, our
version scheme. A PR from `master` would drag all of that into the diff and
would not be mergeable.

```bash
git fetch upstream
git checkout -b upstream/<topic> upstream/main
git cherry-pick <the commits upstream should see>
git push -u origin upstream/<topic>
# open the PR against usestrix/strix:main
```

Everything on `master` is upstream-appropriate **except** these, which must
never appear in an upstream PR:

- `FORK.md` (this file)
- `scripts/release_version.py` and `tests/test_release_version.py`
- the `Resolve version` step and the `display_version` reference in
  `.github/workflows/build-release.yml`
- the `scripts/release_version.py` entry in `pyproject.toml`'s ruff ignores

Cherry-picking the feature commits onto a branch cut from `upstream/main` gives
exactly that split, so the branch is disposable — cut a fresh one whenever you
want to open or refresh a PR.

If upstream merges it, the next sync brings it back through `main` and the
duplicate commits drop out in the merge. If they never do, nothing changes — we
keep shipping it from `master`.
