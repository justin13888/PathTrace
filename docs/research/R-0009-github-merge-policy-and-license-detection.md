# R-0009: GitHub settings for merge-commit-only history; license detection; CI namespaces
- source: https://docs.github.com/en/rest/repos/rules ; https://docs.github.com/en/rest/repos/repos#update-a-repository ; https://github.com/licensee/licensee (content_helper.rb) ; https://github.com/actions/runner-images (Ubuntu 24.04 AppArmor issues) ; https://github.com/jdx/mise-action (v5.1.1)
- accessed: 2026-10-10
- claim-under-test: (a) GitHub can enforce merge-commit-only PRs with no force-push or deletion while a solo maintainer can still merge their own PRs; (b) a verbatim apache.org LICENSE is detected as Apache-2.0; (c) unprivileged user namespaces work on GitHub's Ubuntu 24.04 runners.
- verdict: confirmed
- applicability: REQ-REPO-004, REQ-REPO-006, and the CI netns tests (REQ-DRV-013).
## Evidence
- Repository settings `allow_merge_commit=true, allow_squash_merge=false, allow_rebase_merge=false` plus a ruleset with `deletion`, `non_fast_forward`, `pull_request{required_approving_review_count: 0, allowed_merge_methods: ["merge"]}` and `required_status_checks`. With `bypass_actors: []` nobody can bypass, admins included. With a review count of 0 the author can merge once checks pass.
- licensee strips content before matching and uses a Dice similarity threshold of 98. A sibling repo of the same owner with the apache.org text (minus the leading blank line) is reported as `Apache-2.0` by the GitHub API.
- Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`). `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` per job lifts it; the image-default change was declined upstream.
- `ubuntu-24.04-arm` is a standard hosted runner for public repositories.
## Implications for PTF / probe
- Not applicable to the format. The repository applies these settings (ruleset "Protect main") after the first CI run, so the check names exist.
- netns integration tests can run in CI on x86_64 and aarch64 after the sysctl.
