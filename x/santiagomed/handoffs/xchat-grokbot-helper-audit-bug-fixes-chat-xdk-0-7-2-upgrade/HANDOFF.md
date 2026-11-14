# Handoff: xchat-grokbot-helper audit, bug fixes and chatxdk 0.7.2 upgrade

The coordinator of the outgoing Cursor Project "xchat-grokbot-helper: audit, bug fixes, chat-xdk 0.7.2 upgrade" wrote this on 2026-11-14 (UTC). The Project is moving to another Cursor team, and the Project that replaces it there runs from this file alone. The outgoing Project is shut down. Its threads are stopped, and it holds no subscriptions, timers or routines, so the same work can't run in two places.

## Start here

1. Check the two embedded files at the end against their sha256 values.
2. Read "Standing rules" before touching the repo.
3. Nothing is in flight and nothing is waiting on you. Don't start anything under "Next steps and open questions" unless Santi asks. Each item there has a default.

## Where the work stands

- Repo: [xdevplatform/xchat-grokbot-helper](https://github.com/xdevplatform/xchat-grokbot-helper). It's public, and its default branch is `main`.
- Everything is merged. `main` is at `afac39c6f7bef5bd2686392378b983fa3a14f7da` ("Merge pull request #17"). The Tests workflow passed there on 2026-11-07 in both of its jobs, `unittest (3.10)` and `unittest (3.12)`.
- `main` now has:
  - the CI workflow (#11);
  - the Juicebox fix (#12);
  - the saved-key, stdin and media fixes (#14, #15, #16);
  - the chatxdk 0.7.2 upgrade (#17);
  - Santi's README commit `2682b89defc250251c92f08d0440f311bd528ac0`, which he pushed to #17's branch.
- How #14, #15 and #16 got to `main`:
  - They were based on #11's branch so their checks would run, and they were merged into that branch after #11 had already merged.
  - #17's branch then merged `main` (`6659b44ec65cff456efa5895a201652e80c89325`) and #11's branch (`a42d0f6506bbf91352bb79ad69bd12d58ba5069d`). Its conflicts with #15 and #16 were resolved in those merge commits.
  - Santi then merged #17.
  - #18, a duplicate PR that carried the same three fixes, shows as merged because its head commit reached `main` through #17.
- Tests: `test_xchat_lite.py` has 92 tests, and all of them pass on chatxdk 0.7.2. CI installs `requirements.txt`, which pins `chatxdk==0.7.2`.
- No PRs are open, no tracker tasks are open, and there are no review threads.

## Goal

Santi asked for five things, and all five are done.

1. A severity-ranked audit of the repo. It says how each finding was confirmed and labels anything not verified as unverified. This is `docs/audit-report.md`, embedded below.
2. Non-draft PRs that fix the real bugs, with the Chat XDK upgrade in its own PR.
3. The upgrade to Chat XDK 0.7.2, adapted to its API changes, built and tested. The repo is Python and uses the PyPI package `chatxdk`, not the npm package `@xdevplatform/chat-xdk`. So the target is `chatxdk` 0.7.2, the same release as npm 0.7.2.
4. Green CI on every PR. He then asked for a small GitHub Actions workflow in its own PR against `main`, with the other PRs based on it so their checks ran.
5. A final report covering:
   - each PR in plain English: what it changes, what a bot developer using the script sees today, what changes for them, and why;
   - the breaking changes from 0.5.2 to 0.7.2, and how the script handles each one;
   - the remaining findings and anything unverified.

   This is `docs/final-report.md`, embedded below. It was written to Santi, so "you" in it means Santi.

## Standing rules

These come from Santi and are still in force.

- Don't merge PRs. Santi merges them himself.
- Never force-push any branch, and never push to `main` directly. Push normal commits to feature branches only.
- Don't change repo settings or secrets.
- Don't publish anything to npm or PyPI.
- If something needs real X credentials to test end to end, say so, and explain how you tested it instead.
- Open PRs ready for review, not as drafts. Keep dependency upgrades out of bug-fix PRs.
- CI must be green on every PR. If CI fails, fix it.
- Explain each PR in plain English: what it changes, what a bot developer using this script sees today, what changes for them, and why.
- Rank findings by severity, say how each one was confirmed, and label anything not verified as unverified.
- Check every file before you commit it. Never commit env files, shell history or other sensitive files.
- Don't send company information, code, credentials or secrets to public or unapproved services.
- If a PR is for a Linear ticket, put `Resolves <ID>` in its body.
- Never open or print `~/.grok/config.toml`.

## Decisions

- **Upgrade target.** The target is PyPI `chatxdk` 0.7.2, pinned in a new `requirements.txt` that CI installs. The optional `keyring` dependency stays unpinned.
- **CI.** `.github/workflows/tests.yml` runs the unittest suite on Python 3.10 and 3.12, with read-only permissions. It runs on every pull request, whatever its base branch, and on every push to `main`.
- **Image sending.** Sending follows chatxdk 0.7's flow, in this order:
  1. `prepare-media`;
  2. the upload initialize call;
  3. `session-encrypt` with `media`;
  4. append, finalize and send.

  `encrypt-media` is hidden from `--help`. Calling it exits with one line pointing to the new flow.
- **Event field names.** Decrypted events use chatxdk 0.7's field names. `target_message_id` changed meaning in 0.7, so callers should read `target_message_sequence_id` instead. The README and #17's description warn about this.
- **Key version default.** `--key-version` still defaults to `"1"` (audit finding L3), because requiring it would break existing callers. Santi's README commit tells callers to pass it on every run, set to the `public_key_version` from `get_users_public_key`.
- **Per-message-key sends.** Per-message-key (v1) sends switch on only after chatxdk's background request to `api.x.com/2/chat/features` comes back. This script's runs are short and usually encrypt before then, so its sends usually stay on the shared-key (v0) format. Santi's README commit documents this.
- **How #14, #15 and #16 landed.** Santi chose to land them through #17, by merging #11's branch into #17's branch, rather than through a separate PR. #18 needed no action.
- **license/cla.** The `license/cla` check (cla-assistant) stayed pending on every PR. The commits are authored as Cursor Agent, which can't sign the CLA. Santi merged without it, and the task to make it pass was dropped.

## Findings

The audit found 1 high, 3 medium and 12 low findings, plus build and dependency notes D1 to D7. Its line numbers refer to `xchat_lite.py` at `673a442fce5fed6a06a8c69e95b380b8f25cfbc4`, which was `main` before these PRs. The embedded reports have the full details.

Fixed and merged:
- H1 and L2, in #12;
- M1 and L1, in #15;
- M2 and L7, in #14;
- M3, in #16;
- L4, in #17.

#17 also addressed D1 and D5, and #11 addressed D2.

Still open, all low or informational:
- **L3:** `--key-version` silently defaults to `"1"`. The README now tells callers to pass it.
- **L5:** `encrypt --conversation-key-b64` takes a conversation key on the command line, and `prepare-keys` prints one. Both are documented behavior.
- **L6:** with no PIN given, the script reads `CHAT_PIN` from a `box-secrets.json` file. The README doesn't mention that file.
- **L8 (unverified):** `decrypt-media` compares `size_bytes` strictly, so a size given as a string would reject a correct download.
- **L9 (unverified):** `decrypt-media` output file names can collide.
- **L10:** the module docstring advertises `encrypt --from-decrypt` and `--from-prepare` flags that don't exist.
- **L11 (unverified):** entity offsets are counted in UTF-16 units, while chatxdk 0.7 documents UTF-8 bytes. Nothing breaks today.
- **L12:** a reply to an edited message quotes the pre-edit text, because `reply_to_edit_event` isn't passed.
- **D3:** no Python dependency audit (`pip-audit`) has been run. chatxdk declares no Python dependencies.
- **D6:** there's no `.gitignore`, so test runs leave an untracked `__pycache__/`.

These weren't verified, because they need real X credentials or a real X client:
- a real Juicebox PIN unlock, and the real wrong-PIN message;
- a real upload and send through X's tools;
- how X apps render images in per-message-key messages, and which key they use for that media;
- what recipients see when the key version is wrong;
- whether real Juicebox configs are long enough to trigger H1.

Per-message-key behavior was tested only against a local stand-in for X's feature-switch endpoint, using chatxdk's test keys.

## Links

- Repo: https://github.com/xdevplatform/xchat-grokbot-helper
- CI workflow: https://github.com/xdevplatform/xchat-grokbot-helper/blob/main/.github/workflows/tests.yml
- chat-xdk changelog, covering 0.7.0, 0.7.1 and 0.7.2: https://github.com/xdevplatform/chat-xdk/blob/v0.7.2/CHANGELOG.md
- chatxdk 0.7 Python migration guide: https://github.com/xdevplatform/chat-xdk/blob/v0.7.2/docs/migrating-0.7/python.md

## People

- **Santiago Medina Rolong** ("Santi", GitHub `santiagomed`) asked for this work, set the rules above, and merges PRs himself. Cursor agents opened the PRs under his GitHub account, and the commits are authored as Cursor Agent. He wrote the README commit on #17.
- Nobody else took part. No one reviewed the PRs, and the only comments on them are CLAassistant's requests to sign the CLA.
- The repo's only open issue, [#10](https://github.com/xdevplatform/xchat-grokbot-helper/issues/10), is unrelated to this work and was left alone.

## PRs, diffs and review threads

All seven PRs are merged. Merge times below are UTC on 2026-11-07. Their head branches still exist, because the repo doesn't delete branches on merge.

| PR | Title | Head branch | Base | State |
|---|---|---|---|---|
| [#11](https://github.com/xdevplatform/xchat-grokbot-helper/pull/11) | Run the unittest suite on GitHub Actions | `cursor/unittest-ci-workflow-aeae` | `main` | Merged at 08:30 |
| [#12](https://github.com/xdevplatform/xchat-grokbot-helper/pull/12) | Read inline juicebox JSON without treating it as a path | `cursor/juicebox-config-input-b729` | `main` | Merged at 08:30 |
| [#14](https://github.com/xdevplatform/xchat-grokbot-helper/pull/14) | Keep the saved key safe when the OS keyring errors or a save fails | `cursor/saved-key-keyring-errors-b729` | `cursor/unittest-ci-workflow-aeae` | Merged into #11's branch at 08:30; reached `main` through #17 |
| [#15](https://github.com/xdevplatform/xchat-grokbot-helper/pull/15) | Reject malformed stdin instead of sending the wrong message or crashing | `cursor/stdin-input-validation-b729` | `cursor/unittest-ci-workflow-aeae` | Merged into #11's branch at 08:31; reached `main` through #17 |
| [#16](https://github.com/xdevplatform/xchat-grokbot-helper/pull/16) | Keep media_hash_key on attachments the helper decodes itself | `cursor/media-hash-key-attachments-b729` | `cursor/unittest-ci-workflow-aeae` | Merged into #11's branch at 08:31; reached `main` through #17 |
| [#17](https://github.com/xdevplatform/xchat-grokbot-helper/pull/17) | Upgrade to chatxdk 0.7.2 | `cursor/chatxdk-0-7-2-upgrade-c25e` | `main` | Merged at 08:37 |
| [#18](https://github.com/xdevplatform/xchat-grokbot-helper/pull/18) | Land the fixes from #14, #15 and #16 on main | `cursor/land-merged-fixes-b729` | `main` | Shown as merged at 08:37, once its head reached `main` through #17 |

There is no #13. PRs #1 to #9 came before this work.

- **Diffs:** none. No other diffs or patches were opened, and no thread holds unpushed work.
- **Review threads:** none on any of these PRs, open or resolved.

## Tracker tasks

No tasks are open, so nothing needs to be recreated. For reference, the old tracker closed with these 12 tasks:

- Done: Audit the repo for bugs, security, and build problems (`docs/audit-report.md`).
- Done: Write the final report on PRs and remaining findings (`docs/final-report.md`).
- Done: Stack the bug-fix and upgrade PRs on a new CI PR. This parent task had three children:
  - Done: Add CI that runs the tests on every PR (#11).
  - Done: Fix the confirmed audit bugs in reviewable PRs. This parent task had five children, all done:
    - Keep Juicebox auth tokens out of config crash output (#12).
    - Keep saved keys working when the keyring or a save fails (#14).
    - Reject malformed stdin instead of sending the wrong message (#15).
    - Keep media hash keys on attachments the helper decodes (#16).
    - Land the saved-key, stdin and media fixes on main (#17 and #18).
  - Done: Upgrade to Chat XDK 0.7.2 in its own PR (#17).
- Canceled: Get the license/cla check passing on every PR.

If Santi asks for any item under "Next steps and open questions", create one task for each item.

## Subscriptions, timers and routines

Nothing is active. Every watch had already closed by the time of this handoff, so none needed removing. Each thread's list was checked on 2026-11-14.

| Holder | What it watched | Expiry | Removed |
|---|---|---|---|
| Project coordinator | GitHub PR events on #11, #12, #14, #15, #16, #17 and #18, with one PR-scoped subscription each | Each one closed itself when its PR merged, between 08:30 and 08:37 UTC on 2026-11-07 | Already closed. The list was empty, so nothing was left to remove |
| Chat XDK 0.7.2 upgrade | #17's CI and merge state | Ended when #17 merged | Already closed. Its list was empty |
| Audit and bug fixes | Nothing | None | Its list was empty |
| Unittest CI workflow | Nothing. It checked #11's CI by hand and never subscribed | None | Its list was empty |

No thread had a timer, and the Project had no routines. The successor doesn't need any subscriptions now. If it opens a PR, it can watch that PR then.

## Threads and what each owned

All four threads are stopped. None had unpushed work, background processes or tmux sessions.

- **Project coordinator** owned the tracker, `docs/final-report.md`, the PR subscriptions above, and this handoff.
- **Audit and bug fixes** owned the audit (`docs/audit-report.md`), #12, #14, #15, #16 and #18, and their branches. Its owner handoff lists the open findings L3, L5, L6, L8, L9, L10, L11, L12, D3 and D6 as what's left.
- **Chat XDK 0.7.2 upgrade** owned #17 and `cursor/chatxdk-0-7-2-upgrade-c25e`, including the merges that brought in #14 to #16 and the run of all 92 tests. Its owner handoff lists L3, L10, L11 and D6 as what's left, along with the lack of an end-to-end test with real X credentials.
- **Unittest CI workflow** owned #11 and `cursor/unittest-ci-workflow-aeae`. Nothing is left for it.

## Next steps and open questions

None of these is required, and nothing is waiting on the successor. Use each default unless Santi says otherwise.

1. **Small follow-ups (L10, L12, D6).** Default: don't start them unprompted. If Santi asks, open one small, ready-for-review PR against `main` for each:
   - remove the nonexistent flags from the module docstring (L10);
   - pass `reply_to_edit_event` when replying to an edited message (L12);
   - add a `.gitignore` for `__pycache__/` (D6).
2. **Should `--key-version` become required (L3)?** Default: no. Keep the `"1"` default and the README guidance, because requiring the flag breaks existing callers. If Santi wants a change, make it its own PR and say clearly that it breaks callers.
3. **Should the README warn about L5 and L6?** Default: not until Santi asks. Then document two things:
   - the conversation key on the command line and in `prepare-keys` output (L5);
   - the `box-secrets.json` PIN fallback (L6).
4. **The unverified items (L8, L9, L11, and the checks that need real credentials).** Default: leave them labeled unverified. They need real X credentials or a real X client.
5. **Dependency audit (D3).** Default: if the new environment can reach PyPI, run `pip-audit -r requirements.txt` once and report the result. Don't open a PR unless it finds something.
6. **Merged PR branches on the remote.** Default: leave them. Delete them only if Santi asks.
7. **`license/cla` on future agent PRs.** Default: expect it to stay pending, and tell Santi. Don't re-author commits or force-push to clear it.
8. **This handoff branch.** Default: leave it as it is, with no PR. Santi decides whether to keep it.

## Embedded store files

Two files from the outgoing Project's store follow, byte for byte.

- Each block starts with a BEGIN line that gives the file's path, its byte count and the sha256 of its exact bytes. It ends with an END line.
- The content is exactly that many bytes, starting right after the BEGIN line.
- Both files end in a newline, so no newline was added before END.

The two files:
- `docs/final-report.md` is the final report. On 2026-11-14 it was updated to show that everything merged, and internal links were removed.
- `docs/audit-report.md` is the severity-ranked audit. It got the same update.

These were left out on purpose:
- the preferences file;
- the old notes and tracker copy, which the task list above replaces;
- subscription event logs;
- an internal upgrade report, whose content is in `docs/final-report.md` and #17's description.

@@BEGIN@@ path=docs/final-report.md bytes=20477 sha256=3b9c8adeebde40bcc070bdefc1d5f4adfa363e52d6f2347a4102b662f855e54d
# Final report: xchat-grokbot-helper audit, bug fixes and chatxdk 0.7.2 upgrade

Everything is merged into main on [xdevplatform/xchat-grokbot-helper](https://github.com/xdevplatform/xchat-grokbot-helper) as of Nov 7, 2026, and CI on main passes on Python 3.10 and 3.12. #11 and #12 merged into main directly. #14, #15 and #16 were merged into #11's branch, because they still targeted it, and reached main through #17, which carries them. [#18](https://github.com/xdevplatform/xchat-grokbot-helper/pull/18), a duplicate PR that carried the same three fixes, also shows as merged. The `license/cla` check stayed pending on every PR, and the PRs were merged without it.

The repo is a single Python script, `xchat_lite.py`, with a unittest suite. It doesn't use the npm package `@xdevplatform/chat-xdk`. It uses `chatxdk`, the Python package built from the same [chat-xdk](https://github.com/xdevplatform/chat-xdk) repo, so the upgrade targets `chatxdk` 0.7.2, the same release as npm 0.7.2.

The full audit, with line numbers and how each finding was confirmed, is in the [Audit report](audit-report.md). It found 1 high, 3 medium and 12 low findings. The PRs fix the high, all three mediums and four of the lows; the rest are listed under [Findings not fixed](#findings-not-fixed-and-why).

## PRs and how they landed

| PR | Subject | Severity |
|---|---|---|
| [#11](https://github.com/xdevplatform/xchat-grokbot-helper/pull/11) | CI workflow that runs the unittest suite | |
| [#12](https://github.com/xdevplatform/xchat-grokbot-helper/pull/12) | Juicebox config crash that prints auth tokens | High |
| [#14](https://github.com/xdevplatform/xchat-grokbot-helper/pull/14) | Saved key when the OS keyring errors or a save fails | Medium |
| [#15](https://github.com/xdevplatform/xchat-grokbot-helper/pull/15) | Malformed stdin sends the wrong message or crashes | Medium |
| [#16](https://github.com/xdevplatform/xchat-grokbot-helper/pull/16) | Missing `media_hash_key` on attachments the script decodes itself | Medium |
| [#17](https://github.com/xdevplatform/xchat-grokbot-helper/pull/17) | Upgrade to chatxdk 0.7.2 | |

Every PR after #11 was first based on #11's branch so its checks would run. #11 merged into main first, then #12. #14, #15 and #16 were merged while they still targeted #11's branch, so they landed there instead of on main. #17 brought them to main: main and then #11's branch were merged into #17's branch, #17's conflicts with #15 and #16 were resolved in those merge commits, and #17 then merged. The merged code passes 92 tests on chatxdk 0.7.2.

## Each PR in plain English

### #11: Run the unittest suite on GitHub Actions

- **What it changes:** adds `.github/workflows/tests.yml`. On every pull request, whatever its base branch, and every push to `main`, it installs chatxdk 0.5.2 on Python 3.10 and 3.12 and runs the existing tests; #17 later switched the install to `requirements.txt`, which pins 0.7.2. It has read-only permissions and uses current action versions. The script itself is untouched.
- **What a bot developer sees today:** no automated checks at all. Whether a change breaks the script is known only if someone runs the tests locally against the right chatxdk version.
- **What changes for them:** every PR shows a pass or fail check before review.
- **Why:** the script depends on exact chatxdk behavior, and the upgrade needed proof that it works against the published package.

### #12: Read inline Juicebox JSON without treating it as a path (high)

- **What it changes:** a `--juicebox` or `XCHAT_JUICEBOX_JSON` value that starts with `{` is used as JSON and never checked as a file path. Any other value is read as a file, and if that fails the script exits with a short message that names the problem without repeating the value.
- **What a bot developer sees today:** a long inline config (over 4096 bytes, or with a first `/`-separated chunk over 255 bytes) crashes with "File name too long". The crash output prints the whole config, including the Juicebox auth tokens in `token_map`, to stderr and to any log that captures it. Separately, a mistyped config path fails with a misleading "Invalid JSON" error.
- **What changes for them:** inline configs of any length work, failures never echo the config, and a bad path says the file can't be read.
- **Why:** auth tokens in logs are a credential leak, and the README itself says never to log them.
- **How it was confirmed:** reproduced with the real command line and a fake token, and pinned with tests that fail before the fix and pass after. **Unverified:** whether real X Juicebox configs are long enough to trigger it. Several realms, each with a long token, could be.

### #14: Keep the saved key safe when the OS keyring errors or a save fails (medium)

- **What it changes:** keyring errors while saving, loading or forgetting a key become one-line warnings instead of aborting. Saving now writes the new key first, either to the OS keyring or to a mode-600 key file through an atomic replace, and deletes the old copy only after that write succeeds.
- **What a bot developer sees today:** with a locked keyring or no D-Bus session, `--remember-key` reports `key_saved: false` and saves nothing. The README promises a fallback to the key file, but it never runs, so every run needs the PIN. `forget` crashes with a traceback. And if a save fails, for example on a full disk, the previously saved key has already been deleted.
- **What changes for them:** the documented fallback works, `forget` reports normally, and a failed save leaves the old key in place.
- **Why:** key storage shouldn't silently lose a key, or fail to keep one the docs say is saved.

### #15: Reject malformed stdin instead of sending the wrong message or crashing (medium)

- **What it changes:** `session-encrypt` fails with a clear message when `reply_to` or `edit` isn't a usable id. Every command checks that stdin is valid JSON of the right shape and that list fields are lists, and it does so before unlocking.
- **What a bot developer sees today:** an agent that passes `"edit": {"sequence_id": "2001"}` gets no error. The option is dropped and a brand-new message is encrypted, so an intended edit posts as a duplicate, and an intended reply loses its quote. Other wrong shapes cause Python tracebacks, and an `events` value passed as a string comes back as one garbage row per character.
- **What changes for them:** each bad input gets a one-line error naming the field to fix, well-formed input behaves exactly as before, and bad input no longer costs a Juicebox round trip.
- **Why:** silently sending the wrong message is worse than failing.

### #16: Keep media_hash_key on attachments the helper decodes itself (medium)

- **What it changes:** chatxdk 0.5.2 can't decode per-message-key messages or Grok replies, so the script decodes them itself. Their attachments now keep `media_hash_key`, and an empty key no longer matches an attachment that has none.
- **What a bot developer sees today:** those attachments have no `media_hash_key`, so the bot can't tell which upload to download. `decrypt-media` answers "no decrypted message references this media_hash_key" even when the right event is in its input.
- **What changes for them:** the key is there, and `decrypt-media` finds the message.
- **Why:** the README's download-and-decrypt flow breaks for these messages.
- **Unverified:** which key X apps use for media in per-message-key messages. If it isn't the conversation key, `decrypt-media` on 0.5.2 now reports a decryption failure instead of "not found". After #17, chatxdk decodes per-message-key messages itself and `decrypt-media` uses chatxdk's `decrypt_file`, which derives the file key from the message, so #16 then matters mainly for Grok replies.

### #17: Upgrade to chatxdk 0.7.2

- **What it changes:** moves chatxdk from 0.5.2 to 0.7.2, pinned in a new `requirements.txt` that CI installs, with the README to match, and adapts the script to the 0.7 API. When it was opened, 80 tests passed on 0.7.2 (main had 72); with the bug fixes merged in, 92 pass. CI passes on Python 3.10 and 3.12 with 0.7.2 installed from PyPI.
- **What a bot developer sees today:** the README pins chatxdk below 0.6, which installs 0.5.2. Installing 0.7 breaks every command: `import_keys` and `set_identity` raise `TypeError`, and the media commands call functions that no longer exist.
- **What changes for them:**
  1. Install chatxdk 0.7.2, which needs Python 3.10 or newer.
  2. Sending an image happens in a new order: `prepare-media` (checks each image and returns the upload size, without encrypting), then `chat_media_upload_initialize`, then `session-encrypt` with `media` (builds the message, encrypts each image from that message and writes the upload parts), then append, finalize and send. `encrypt-media` is hidden from `--help`, and calling it exits with one line pointing to the new flow.
  3. Send output gains `xdk_version`, which the X API's send request takes. Image attachments now carry `plaintext_sha256`.
  4. Decrypted events use chatxdk 0.7's field names: `conversation_key_version` (was `key_version`), `target_message_sequence_id` (was `target_message_id`), `updated_text` (was `new_text`) and `sequence_ids` on deletes (was `message_ids`). Display text and notices keep their meaning.
  5. **Watch out for `target_message_id`.** On 0.5.2 it held the target message's sequence id, such as `"2001"`, on reactions, reaction removals and edits. On 0.7.2 it's missing on reactions and ordinary edits, and on an edit sent with per-message keys it holds a UUID message id. Code that keeps reading it gets `None` or a UUID with no error. Read `target_message_sequence_id` instead. The README and the PR description both warn about this.
  6. chatxdk now makes one network request of its own: an anonymous request to `api.x.com/2/chat/features` on a background thread, every 5 minutes, to read X's feature switches. Sends use per-message keys only once that request has come back with them switched on; until then, or if it's blocked, they stay on the older shared-key format. Each run of this script is a short process that usually encrypts before the request comes back, so its sends usually stay on the shared-key format even after X switches per-message keys on. Your README commit on this PR says so. Shared-key messages stay readable by apps on chatxdk 0.5.x and 0.7, but apps on 0.5.x can't read per-message-key messages.
  7. A wrong PIN, a failed unlock, or a non-numeric user id or key version now ends in one line instead of a traceback. A wrong PIN also shows the guesses Juicebox says are left.
- **Why:** 0.6 and 0.7 removed or renamed nearly every call the script makes. And when a send does use per-message keys, images encrypted the old way, under the conversation key before the message exists, can't be opened by recipients.

#### Breaking changes from 0.5.2 to 0.7.2, and how the script handles each

Sources: the chat-xdk changelog for [0.7.0](https://github.com/xdevplatform/chat-xdk/blob/v0.7.2/CHANGELOG.md#070---2026-10-27), [0.7.1](https://github.com/xdevplatform/chat-xdk/blob/v0.7.2/CHANGELOG.md#071---2026-10-28) and [0.7.2](https://github.com/xdevplatform/chat-xdk/blob/v0.7.2/CHANGELOG.md#072---2026-11-02), the [Python migration guide](https://github.com/xdevplatform/chat-xdk/blob/v0.7.2/docs/migrating-0.7/python.md), and a source diff between the `v0.5.2` and `v0.7.2` tags.

Calls and data shapes the script uses:
- `import_keys(keys, version=)` now takes `ImportKeysParams(keys, signing_key_version=)`. Loading a saved key uses it.
- `set_identity(user_id, version)` now takes `SetIdentityParams`, and user ids and key versions must be strings of digits. Updated, and a bad value fails at unlock with a short message.
- `decrypt_events` now takes `DecryptEventsParams`, and its result moved from `messages` to `events`. Updated.
- `encrypt_message`, `encrypt_reply`, `encrypt_add_reaction`, `encrypt_remove_reaction` and `encrypt_edit` take params classes. Updated.
- `prepare_conversation_key_change` takes `ConversationKeyChangeParams`, and its public-key inputs were renamed to `identity_public_key` and `public_key_version`. `prepare-keys` and `session-encrypt`'s `prepare` accept both the old and new names, so existing input keeps working.
- Prepared key changes return new fields (`conversation_participant_keys`, `encrypted_conversation_key`, and nested `action_signatures` that include `signing_public_key`). The script passes them through as returned. Without this, `prepare-keys` would crash while trying to print raw key bytes.
- The send payload's fields were renamed to `encoded_message_create_event` and `encoded_message_event_signature`, and `xdk_version` was added. Updated, and `xdk_version` is now in the output.
- `encrypt_stream`, `decrypt_stream` and `encrypted_stream_size` are gone. Files are now encrypted from their message with `encrypt_file`, decrypted with `decrypt_file` and sized with `encrypted_file_size`. This is the new image flow above, and `decrypt-media` uses `decrypt_file`.
- `Chat.encrypt` is gone. Only the tests used it; they now build their own encrypted boxes, cross-checked against `Chat.decrypt`.
- Decrypted event fields were renamed (`key_version`, `target_message_id`, `new_text`, `message_ids`, `seen_until_id`). Display text and notices read the new names, and the output uses them; see the `target_message_id` warning above.
- Group titles and descriptions are now decrypted by chatxdk, and description changes are a native event. They map onto the existing `decrypted_title` and `description` fields, and the script's own description decoder is removed.
- chatxdk drops the title and description re-encryptions that come with a member removal as errors. The script shows them as rows with empty text and a `skipped` reason instead of "[could not read this event]".
- Per-message-key messages now decrypt and verify inside chatxdk, and their attachments keep `media_hash_key`. The script's own decoder for them, which didn't verify signatures, is removed. Grok messages, pins, unpins and calls are still unknown to chatxdk 0.7.2, so the script keeps decoding those itself.
- The latest conversation key version now comes only from a verified key change. `prepare-media` requires one, as `encrypt-media` did.
- Errors are now typed subclasses of `ValueError`, and a wrong PIN reports the guesses left. The script's existing error handling catches them, and unlock and identity errors print one line.

Runtime behavior:
- Per-message-key sends are switched on by X through the background feature-switch request. The README documents this, including that this script's short runs usually encrypt before the switch arrives. The tests point that request at a dead local port to exercise the old format, and at a local stand-in server to exercise the new one.
- In 0.7.2, key changes, group changes and deletes sent with per-message keys sign at a new signature version. The script only signs key changes, which chatxdk handles, so nothing changes.
- Entities, attachments, URL cards and posts are now validated. The script's entity kinds are all valid, and its offsets stay within chatxdk's bounds. Attachments passed through `session-encrypt` are now checked by chatxdk.
- Reply previews must match their quote exactly, and replies built from explicit fields need `reply_to_message_id`. The script builds replies from the replied-to event, so nothing changes.
- Media attachments gain `plaintext_sha256`, which the script now sends.
- `export_keys` raises when no keys are loaded. The script only calls it after unlocking.
- An empty Juicebox config now fails when the chat is created. The script already rejects an empty config before that.
- Python 3.10 or newer is required. This is documented, and CI runs 3.10 and 3.12.
- Breaking changes in APIs the script doesn't use need no change: key registration, single-event decrypt, deletes and read receipts, group management, `sign`, and the renamed stream encryptors. chat-xdk 0.7.3 only changes the browser JavaScript package, so it doesn't affect Python.

## Findings not fixed, and why

- **`--key-version` silently defaults to `"1"` (low).** An account on another signing-key version signs with the wrong one. That matters more under 0.7, where a per-message-key signature names the key version. The default isn't changed because requiring the flag would break existing callers, and chatxdk 0.7.2 offers no way to read the account's version. Your README commit on #17 now tells callers to pass `--key-version` on every run, set to the `public_key_version` from `get_users_public_key`, and says recipients can't verify messages signed under the wrong version; that wasn't tested here. The recommended follow-up is still to require the flag, or to look the version up with `get_users_public_key`.
- **Conversation keys on the command line and stdout (low).** `encrypt --conversation-key-b64` puts a key where `ps` and shell history can see it, and `prepare-keys` prints `_local_conversation_key_b64`. Both are documented behavior, and changing them changes the interface. A README warning is the recommended follow-up.
- **Undocumented PIN fallback (low, informational).** With no PIN given, the script reads `CHAT_PIN` from `/home/box/agent-data/box-secrets.json` or `~/agent-data/box-secrets.json`. The README doesn't mention either path. Documenting or removing it is the recommended follow-up.
- **The module docstring advertises `encrypt --from-decrypt` and `--from-prepare` flags that don't exist (low).** #17 rewrote the neighboring docstring lines, so the fix waited for #17 to merge. It's now a one-line follow-up.
- **Replies to an edited message quote the original text (low).** The script never passes the edit event (`reply_to_edit_event`) when building a reply, though both chatxdk 0.5.2 and 0.7.2 accept it. Nothing fails; the quote is just stale. This was confirmed by reading the code, not by running it. #17 rewrote that exact reply call, so the fix waited for #17 to merge. It's now a small follow-up.
- **`decrypt-media` compares `size_bytes` strictly (low, unverified).** A size given as a string would reject a correct download. The download tool's documented output uses a number.
- **`decrypt-media` output file names can collide (low, unverified).** Names keep only the letters and digits of `media_hash_key`. Whether real keys contain punctuation is unverified.
- **Entity offsets are counted in UTF-16 units, while chat-xdk 0.7 documents UTF-8 bytes (unverified).** chatxdk passes offsets through unchanged, so nothing breaks today. Which unit X apps expect needs a real client to confirm.
- **No `.gitignore` (hygiene).** Running the tests leaves a `__pycache__/` folder that's easy to commit by accident.

## What couldn't be verified

- Anything that needs real X credentials: a Juicebox PIN unlock (including the real wrong-PIN message), a real upload and send through X's tools, how X apps render images in per-message-key messages, which key X apps use for that media, and what recipients see when the key version is wrong.
- Per-message-key behavior was tested only against a local stand-in for X's feature-switch endpoint, using chatxdk's test keys.
- Whether real X Juicebox configs are long enough to trigger the #12 crash.
- A Python dependency audit: `pip-audit` wasn't run. chatxdk declares no Python dependencies.

## How it was tested

- Local test runs used chatxdk 0.5.2 and 0.7.2 built from their release tags. CI installs the published packages from PyPI.
- Before these PRs, main's 72 tests passed on 0.5.2. Each bug fix adds tests that fail before the fix and pass after; one extra test in #14 guards the new save order and passes on both. #17 ran 80 tests on 0.7.2, a trial merge of the four bug fixes onto it ran 90, and the final merged #17 runs 92.
- The #12 token leak was reproduced with the real command line and a fake token.
- No real X or Juicebox service was contacted. The tests unlock offline with chatxdk's test keys.

## The license/cla check

`license/cla` (cla-assistant) stayed pending on every PR. The commits are authored as Cursor Agent, and nobody here can sign the contributor license agreement for that account, so no code change clears it. You merged the PRs without it, so nothing is waiting on this. Later agent-authored PRs will likely show it pending too, unless a repo admin exempts that account in the cla-assistant settings.
@@END@@ path=docs/final-report.md
@@BEGIN@@ path=docs/audit-report.md bytes=14918 sha256=4c0100a1df30fdb7301b9159e9df92601f190af04bc1d5bff4ce96e1659cbcb2
# Audit: xdevplatform/xchat-grokbot-helper (main @ 673a442)

## Summary

The repo is a single Python CLI, `xchat_lite.py` (about 1,860 lines), with a unittest suite, `test_xchat_lite.py`. It uses the **PyPI package `chatxdk`** (`from chat_xdk import …`), pinned in the README to `<0.6`, which resolves to 0.5.2. It does not use the npm package `@xdevplatform/chat-xdk`, so the "0.7.2 upgrade" means the Python `chatxdk` 0.7.2.

I found one high, three medium and twelve low findings. Five PRs fix the high, the three mediums and four of the lows, and eight lows are still open. The four bug-fix PRs fix H1, M1–M3, L1, L2 and L7. The upgrade PR [#17](https://github.com/xdevplatform/xchat-grokbot-helper/pull/17) fixes L4 and addresses D1 and D5. The CI PR [#11](https://github.com/xdevplatform/xchat-grokbot-helper/pull/11) addresses D2. All of them are merged:

| PR | Theme | Status |
|---|---|---|
| [#11](https://github.com/xdevplatform/xchat-grokbot-helper/pull/11) | CI: GitHub Actions unittest workflow (D2) | Merged into main |
| [#12](https://github.com/xdevplatform/xchat-grokbot-helper/pull/12) | Juicebox config input: crash that leaks auth tokens | Merged into main |
| [#14](https://github.com/xdevplatform/xchat-grokbot-helper/pull/14) | Saved key when the OS keyring errors or a save fails | Merged into #11's branch; reached main through #17 |
| [#15](https://github.com/xdevplatform/xchat-grokbot-helper/pull/15) | stdin validation: wrong message sent, tracebacks | Merged into #11's branch; reached main through #17 |
| [#16](https://github.com/xdevplatform/xchat-grokbot-helper/pull/16) | `media_hash_key` on attachments the helper decodes itself | Merged into #11's branch; reached main through #17 |
| [#17](https://github.com/xdevplatform/xchat-grokbot-helper/pull/17) | Upgrade to chatxdk 0.7.2: one-line unlock errors, `requirements.txt` (L4, D1, D5) | Merged into main |

`license/cla` (cla-assistant) stayed pending on every PR, because the commit author hasn't signed the CLA. The PRs were merged without it.

## How findings were confirmed

- Findings were checked against `chatxdk` 0.5.2 built from tag `v0.5.2` of `xdevplatform/chat-xdk`. CI on #11 installed the published `chatxdk==0.5.2` wheel.
- Baseline on main at 673a442: all 72 tests pass.
- Each finding was confirmed with a repro script or the real CLI against that build, then pinned with a test that fails before the fix and passes after. Real Juicebox and X endpoints were never contacted: there are no real credentials, and the tests unlock offline with the SDK's test-vector keys.

Line numbers refer to `xchat_lite.py` at 673a442, main before these PRs.

## Findings

### High

**H1. A long inline Juicebox config crashes, and the crash prints the config, auth tokens included.** Lines 110–117 (`_load_juicebox_config`). Status: **fixed in [#12](https://github.com/xdevplatform/xchat-grokbot-helper/pull/12).**
- The helper calls `Path(raw).is_file()` on the `--juicebox` / `XCHAT_JUICEBOX_JSON` value even when that value is inline JSON. On Python 3.12, a string over 4096 bytes, or one whose first `/`-separated segment is over 255 bytes, raises `OSError: [Errno 36] File name too long: '<the whole value>'`.
- What a bot developer sees: the command dies with a traceback that contains the full `juicebox_config`, `token_map` Juicebox auth tokens included, on stderr and in any log that captures it.
- How I confirmed it: ran `unlock-check` through the real CLI with a synthetic X-shaped config holding a fake token. The fake token appeared in the traceback before the fix and not after; the config then reached Juicebox, which failed to reach the made-up realm.
- **Unverified:** whether real X `juicebox_config` values are long enough to trigger it. X configs carry a JWT-style token per realm, so several realms could pass 4096 bytes, but I didn't see a real one.
- chatxdk's own config errors (`Invalid JSON…`, `Invalid key_store_token_map_json…`) don't echo the config; I checked.

### Medium

**M1. `session-encrypt` silently sends a new message when `reply_to` or `edit` isn't a plain id.** Lines 486–490 and 509–528 (`_encrypt_action`). Status: **fixed in [#15](https://github.com/xdevplatform/xchat-grokbot-helper/pull/15).**
- `_scalar()` turns an object, list or boolean into `""`, and the option is then ignored.
- What a bot developer sees: an agent that passes `"edit": {"sequence_id": "2001"}` gets back `action: "message"`. Sending it posts a duplicate message instead of an edit. The same happens to a reply, which loses its quote.
- How I confirmed it: CLI repro with test vectors returned a plain message.

**M2. When the OS keyring errors, `--remember-key` saves nothing and `forget` crashes.** Lines 184–196 and 199–208 (`_forget_saved_key`, `_write_saved_key`). Status: **fixed in [#14](https://github.com/xdevplatform/xchat-grokbot-helper/pull/14).**
- `_write_saved_key` first clears the old key with `_forget_saved_key()`, whose keyring calls aren't guarded. If the keyring raises (a locked Secret Service, no D-Bus session), the README's fallback to the mode-600 key file never runs.
- What a bot developer sees: `key_saved: false`, the PIN is needed on every run, and `forget` ends in a traceback.
- How I confirmed it: a fake keyring that raises, run through the CLI.

**M3. Attachments the helper decodes itself lose `media_hash_key`, so `decrypt-media` can't find them.** Lines 851–873 (`_ATTACHMENT_FIELDS`, `_attachment_from_thrift`). Status: **fixed in [#16](https://github.com/xdevplatform/xchat-grokbot-helper/pull/16).**
- This affects messages sent with a per-message key (`contents_encryption_version` 1) and Grok replies. Their media attachments come back without `media_hash_key`.
- What a bot developer sees: `decrypt-media` answers "no decrypted message references this media_hash_key; include its event" even with the right event.
- How I confirmed it: a per-message-key message with a photo, built from the suite's helpers, run through `decrypt` and `decrypt-media`.
- **Unverified:** whether X clients encrypt media in v1 messages under the conversation key. After the fix, a wrong key shows up as a decryption error rather than "not found".

### Low

**L1. Malformed stdin gives Python tracebacks or garbage rows.** Status: **fixed in [#15](https://github.com/xdevplatform/xchat-grokbot-helper/pull/15)**; confirmed by CLI repro.
- Commands affected: `cmd_*` (lines 1675–1793), `_decrypt_media` (line 1481) and `_encrypt_media` (line 1612).
- A bare event list sent to `decrypt-media`, `encrypt-media`, `prepare-keys` or `session-encrypt` raises `AttributeError`. So does `"media": ["path"]` or a non-object `prepare`.
- `"events": "<string>"` is split into single characters, each returned as a `[could not read this event]` row.
- The fix also reads stdin before unlocking, so bad input no longer costs a Juicebox round trip.

**L2. A missing Juicebox config file gives a misleading error.** Lines 110–117. Status: **fixed in [#12](https://github.com/xdevplatform/xchat-grokbot-helper/pull/12)**; confirmed with the real SDK.
- A typo'd path is passed to chatxdk as JSON, which fails with `Invalid JSON: expected value at line 1 column 1`.

**L3. `--key-version` silently defaults to `"1"`.** Lines 270–274. Status: **not fixed** in code; #17's README now tells callers to pass `--key-version` on every run.
- Without `--key-version` or `XCHAT_KEY_VERSION`, the helper calls `set_identity(user_id, "1")`, so an account on a later key version signs with the wrong version. **Unverified:** what recipients then see, which needs an account whose key version isn't 1.
- Not fixed because making the flag required would break existing callers who rely on the default. Recommend failing when it's missing, or reading the version from the SDK if 0.7.x exposes it.

**L4. Unlock and other SDK failures surface as raw tracebacks.** For example, line 287 (`chat.unlock(pin)`). Status: **fixed in [#17](https://github.com/xdevplatform/xchat-grokbot-helper/pull/17)** (the upgrade PR), where unlock and identity errors are now one line.
- With an unreachable realm, the output on main is a traceback ending in `Juicebox error: Transient error`, and I confirmed it contains neither the PIN nor the token. **Unverified:** the error text for a real wrong PIN.

**L5. Conversation keys appear on argv and stdout by design.** Status: **not fixed.**
- `encrypt --conversation-key-b64` takes a conversation key on the command line (lines 1696–1698), where `ps` and shell history can see it.
- `prepare-keys` prints `_local_conversation_key_b64` (lines 340–341, 1720).
- Both are documented. Changing them is an API change; worth a README warning.

**L6. Undocumented PIN fallback.** Lines 120–137. Status: **not fixed** (informational).
- `_load_pin` falls back to reading `CHAT_PIN` from `/home/box/agent-data/box-secrets.json` and `~/agent-data/box-secrets.json`. The README doesn't mention either path.

**L7. A failed save loses the previous key.** Lines 199–220 (`_write_saved_key`). Status: **fixed in [#14](https://github.com/xdevplatform/xchat-grokbot-helper/pull/14).**
- `_write_saved_key` deleted the old key from both the key file and the keyring before writing the new one, so a failed write (a full disk, an unwritable config directory) left no saved key. A save over an existing key happens after the saved key stops matching the account or key version.
- The fix stores the new key first (keyring, or an atomic temp-file write and `os.replace`), and deletes the copy in the other location only after that succeeds.
- How I confirmed it: `test_failed_save_keeps_the_previous_key` makes the file write fail and checks that the previous key file is intact. It failed before the fix.

**L8. `decrypt-media` compares `size_bytes` strictly.** Line 1392. Status: **not fixed.**
- If the tool ever returns `size_bytes` as a string, a correct download would be rejected. **Unverified:** the MCP tool's documented shape shows a number.

**L9. `decrypt-media` output names can collide.** Line 1498. Status: **not fixed.**
- Output file names keep only the alphanumeric characters of `media_hash_key`, so two keys that differ only in punctuation write the same file. **Unverified:** whether real keys contain punctuation; the example key is alphanumeric.

The chatxdk upgrade work surfaced the next three findings. I confirmed each in the code on main at 673a442, and #17 doesn't change any of them.

**L10. The module docstring advertises `encrypt` flags that don't exist.** Line 51. Status: **not fixed.**
- The docstring says `encrypt CONV_ID TEXT` takes `--from-decrypt/--from-prepare`. The parser (lines 1830–1833) defines only `--conversation-key-b64` and `--conversation-key-version`, so following the docstring ends in an argparse "unrecognized arguments" error.
- How I confirmed it: read the docstring and the parser definitions on main.

**L11. Entity offsets are counted in UTF-16 code units, while chatxdk 0.7 documents UTF-8 byte offsets.** Lines 365–439 (`_url_entities`, `_utf16_offset`, `_text_entities`). Status: **not fixed.**
- The helper counts link, mention, hashtag, cashtag and email offsets in UTF-16 code units (lines 380–381 and 424) and passes them to chatxdk unchanged. chatxdk 0.7.2's `docs/API.md` says entity `start`/`end` count bytes of the text's UTF-8 encoding. For ASCII text the two counts are the same.
- What a bot developer sees: nothing breaks. A UTF-16 count is never larger than the UTF-8 byte count for the same text, so 0.7.2's offset check doesn't fail. But for text with non-ASCII characters before an entity, the offsets differ between the two units.
- **Unverified:** which unit X clients expect when they render entities.
- How I confirmed it: read the code on main and the chatxdk v0.7.2 docs.

**L12. A reply to an edited message quotes the original text.** Lines 518–523 (`_encrypt_action`, the `chat.encrypt_reply` call). Status: **not fixed.**
- `session-encrypt` passes the target's original event as the reply target but never passes `reply_to_edit_event`, the companion that carries the target's edit event. chatxdk builds the quoted text from the edit only when that companion is given, so the quote shows the text from before the edit. Both 0.5.2 and 0.7.2 accept `reply_to_edit_event` alongside the original event.
- What a bot developer sees: a bot's reply to an edited message quotes the pre-edit text.
- How I confirmed it: read the `encrypt_reply` call on main, and the `reply_to_edit_event` parameter in the chatxdk Python stubs (`chat_xdk/__init__.pyi`) for 0.5.2 and 0.7.2, and in 0.7.2's `docs/API.md`. I didn't run it.

## Dependencies, build and CI

- **D1. No dependency manifest.** There's no `requirements.txt`, `pyproject.toml` or lockfile on main. `chatxdk` is pinned only in the README (`"chatxdk<0.6"`), and the optional `keyring` isn't pinned at all. Status: **addressed by [#17](https://github.com/xdevplatform/xchat-grokbot-helper/pull/17)**, which adds a `requirements.txt` pinning `chatxdk` 0.7.2 that CI installs. `keyring` stays optional and unpinned.
- **D2. No CI on main.** Main has no checks. Status: **addressed by [#11](https://github.com/xdevplatform/xchat-grokbot-helper/pull/11)**, which adds `.github/workflows/tests.yml` running the suite on Python 3.10 and 3.12. On #17, CI installs from `requirements.txt` instead of the `chatxdk==0.5.2` pin.
- **D3. Audits.** `npm audit` doesn't apply because there's no JavaScript. `pip-audit` wasn't run (**unverified**). `chatxdk` declares no Python dependencies. Status: open.
- **D4. Package name.** The project brief names `@xdevplatform/chat-xdk`, but this repo depends on the Python package `chatxdk`. The upgrade target is `chatxdk` 0.7.2 on PyPI. Status: informational; #17 targets the Python package.
- **D5. What 0.7.2 touches.** Status: **addressed by [#17](https://github.com/xdevplatform/xchat-grokbot-helper/pull/17).** The points as originally raised:
  - The README says 0.6 replaces `encrypt_stream` and `decrypt_stream`, which `encrypt-media` (line 1616), `decrypt-media` (line 1495) and the tests (`EncryptedSizeTest`, the media tests) use.
  - 0.7.2 adds `reply_to_message_id` and `target_message_id` for v1 replies and edits, and `plaintext_sha256` on media attachments. The session-encrypt reply, edit and media paths should be checked against them.
  - If 0.7.x decrypts v1 per-message-key messages, the helper's own decoder (lines 1059–1127, `_open_box`) and #16's change may become redundant.
  - The README wording "chatxdk 0.5.0 returns them as Unknown" needs updating.
- **D6. No `.gitignore`.** Running the tests leaves an untracked `__pycache__/` that's easy to commit by accident. Status: **open.**
- **D7. `license/cla` stayed pending on all PRs**, #11 through #17. The PRs were merged without it. Status: **closed**; later agent-authored PRs will likely show it pending too.
@@END@@ path=docs/audit-report.md
