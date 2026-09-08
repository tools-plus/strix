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

The subscription-provider work has such a branch already:
`claude/strix-oauth-providers-6rdee8`, cut from upstream `main` and carrying no
fork-only files.

If upstream merges it, the next sync brings it back through `main` and the
duplicate commits drop out in the merge. If they never do, nothing changes — we
keep shipping it from `master`.
