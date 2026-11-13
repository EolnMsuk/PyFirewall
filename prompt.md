# PyFirewall 4.3 implementation handoff

You are an expert software security engineer working on PyFirewall, a Windows Python application in `C:\PyFirewall`. It uses Tkinter, Scapy, psutil, and Windows Firewall and supports application and global process/IP/domain/port/protocol/direction rules.

Review and execute `C:\PyFirewall\plan.md`. This is an implementation session: inspect the current source, implement the approved behavior, perform focused validation, and report the result. Do not stop after producing another plan.

## Workflow requirements

1. If any request, instruction, or required behavior is unclear, stop immediately, give a concise list of specific clarification questions, and wait for explicit answers. Do not guess about an unresolved product requirement.
2. Perform all work locally within `C:\PyFirewall`. Do not push changes, tags, or commits to GitHub or any remote repository. Respect the same environment and filesystem restrictions as this session.
3. Focus on necessary changes. Reuse the existing test harness and fixtures. Run only relevant checks and add/extend tests for meaningful gaps; do not generate redundant test suites or run the full suite without a concrete reason.
4. Inspect any applicable `AGENTS.md` before editing. No applicable file or Git repository was found during the planning review; recheck the current workspace without assuming version-control commands are available.

## Required result

- Add Cut to the existing editable-text right-click context menu used in search fields and global-rule add/edit inputs. With selected text, show Cut, Copy, Paste. With no selection, show only Paste. Preserve current Ctrl+X and other keyboard behavior, focus handling, and text undo.
- Show the triggering connection's remote port, protocol, and available domain/hostname in Auto-Block Protection. Apply the temporary block before displaying the prompt. Open the prompt without waiting for DNS; add a hostname later if the same prompt still awaits the user's first choice. Preserve exact connection-decision scope, cancellation, save retries, and owned-hold cleanup.
- Fix first-time Allow Process from Live Monitor and first-time Add App Rule > Allow so both create a persistent Allowed app entry in Managed Rules without requiring an earlier block. Preserve conversion of existing blocks, Auto-Block Allow All, grouping, and independent global rules.
- Set the application version to `4.3` and prepend simple end-user changes under `# 4.3` in `C:\PyFirewall\changelog.md`.

## Blocking questions already answered by the user

The planning session asked whether immediate blocking should always apply when Auto-Block is enabled and whether first-packet prevention was required. The user answered:

> 1. It should immediately block only when Filter All Connections is enabled (or when the threshold set is exceeded).
> 2. Keep the current capture-and-react flow, do not modify it to block first packet(s).

These answers settle the scope. Preserve the existing Filter All/threshold behavior and protection enable/pause controls. Do not redesign capture, change firewall defaults, or introduce a driver to prevent initial packets. Do not add a DNS or presentation delay before starting the existing hold operation.

## Findings to verify before changing code

The planning review was static; it did not modify application code, tests, version constants, or the changelog, and it did not run tests or firewall commands. It created only `plan.md` and this handoff.

- `firewall.py::_commit_rule_batch` builds `apps` for Allow requests but does not plan native application Allow records. Its final condition checks `planned`, `previous`, `affected`, and `decision_guard`, but omits `apps`. For a fresh Allow request, it skips `commit()` and still returns success. Including nonempty `apps` in the transaction condition is the proposed minimal repair. Test the real transaction rather than mocking it away.
- App Allow is stored in `allowed_apps`; `views.py::_make_rule_rows` renders it. Preserve that representation. Do not add native Allow rules merely to make the transaction run. Auto-Block Allow All already uses `allow_executable`, a different commit path.
- The generic batch deliberately excludes temporary holds. Review manual Allow while a prompt is pending so its caller does not discard hold ownership while leaving the native block behind. Preserve unrelated holds, newer generations, and cleanup retry obligations.
- `widgets.py::_bind_entry_menu` is the shared editable-input menu. It currently always shows Copy/Paste and already preserves selection and undo behavior. Existing tests use fixed labels/indexes and need adjustment to the selection-dependent menu.
- `auto_block.py` stores the actual triggering endpoint in `auto_prompt_connections` before queuing the prompt. Port and protocol are already captured. Use that snapshot instead of grouped or newly arriving connections.
- `monitoring.py` already has bounded asynchronous DNS and `_notify_dns_changed`; `app.py::drain_ui_queue` processes coalesced DNS events for Live Monitor and Alerts. Extend this flow to refresh only the active unanswered prompt. Keep display enrichment separate from enforcement and freeze it on the first choice, including during a failed-decision retry.
- Bump `constants.py::__version__` only as the application release identifier. Preserve configuration schema `4.1`, backup version 8, and `4_1_` native-rule names. No new rule reset/migration is required by this task.

## Execution and completion

Read the full plan and relevant current code, then carry out its steps. If the files have changed since the review, reconcile the plan against the source within the confirmed scope and stop for clarification only if a requirement is genuinely unresolved.

Use `python -B tests/run_ui_checks.py` with explicit affected module/class/method selections as described in the plan. The runner stubs Scapy, native operations are mocked by the tests, and fixtures stay in the project's `.validation-tmp` directory. Do not launch the real application or alter the user's firewall policy merely to validate a regression. Update existing real-Tk checks for menu visibility/Cut and prompt details where needed, and extend existing transaction/DNS tests for the identified gaps.

Complete the version and changelog after the implementation is accurate. Check off the plan as work is actually completed. Finish with a concise summary of changed files, the Allow bug's cause and repair, validation commands/results, and any unverified desktop or native enforcement behavior. State accurately what was implemented and tested; keep everything local.
