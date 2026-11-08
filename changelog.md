# 3.4

- Threshold work retains its original detection epoch across queue and firewall-lock waits. Threshold, protection, pause, reset, and capture transitions retire stale work without losing temporary-hold cleanup ownership.
- A bounded native worker runs rule edits, holds, forward DNS, refresh, reset, and orderly shutdown off capture/Tk. Prompt draining never waits on the native lock; shutdown retains machine ownership through cleanup and profile restoration.
- Native refresh and startup share reconciliation of enabled state, actions, directions, executable group members, protocols, ports, addresses, and profile coverage. Saved intent survives drift, Managed Rules reports missing/disabled/partial/changed enforcement, and unverified global rules do not suppress protection. Reapply uses the normal verified transactions.
- An applied Auto-Block decision with a failed save can retry persistence without another native mutation. Settings, reset, preferences, and orderly exit report save failures. Nonfinite/nonpositive threshold floats are rejected before mutation, with strict finite JSON serialization as a backstop.
- One global native-policy mutex coordinates copies, Windows sessions, setup, and uninstall. Setup/uninstall require an orderly tray Close instead of terminating Python processes, and setup preserves outstanding recovery journals. Close all older releases before first launching 3.4.
- Login tasks explicitly request unlimited execution. Existing tasks belonging to this installation migrate only their execution limit to PT0S while preserving startup choice and other settings; unrelated tasks remain untouched.
- Legacy domain backups retain validated fallback addresses for offline import; format 7 and executable scopes remain compatible.
- Alert delivery and rate-key admission are bounded, with saturation counters in Alerts. Clear Alerts also clears queued history; active rate windows and lifetime rule traffic totals survive pruning.
- Live Monitor identifies its single capture adapter. Documentation explains reactive Auto-Block timing, profile defaults, application Allow exclusions, managed-rule ownership, overload limits, and update-before-replacement shutdown order.

# 3.3

- A single left click on the tray icon now restores and raises the existing main window, preserving maximized state, normal geometry, and dialog focus. Tray Show, Settings, and second-launch requests share this restore path.
- Live Monitor and Managed Rules now show **Download** and **Upload**, including their column choosers. Saved column IDs/layouts, numeric sorting, MB-formatted values, and CSV headers remain compatible.
- Fixed tray stop-before-ready races, initialization failure reporting, taskbar recreation recovery, and native resource ownership/cleanup. An unavailable tray keeps a taskbar route and an orderly exit available.
- Bounded and reassembled second-launch activation requests, closed failed listener sockets, and stopped startup when the single-instance mutex cannot be acquired.
- Serialized settings snapshots, writes, failure cleanup, and save status; detached nested preferences/policies; retried outstanding saves for duplicate single-rule requests. Reset now clears pending startup rules together with the committed native deletion.
- Invalid or unreadable saved policy is preserved, reported, and protected from automatic overwrites or new policy application for that run. Outstanding firewall profile recovery still runs first.
- Rule refreshes now reconcile caches under the firewall lock, render detached policy snapshots, reject superseded results/errors, and wait for this run's initialization. Filtered-rule removal/replacement retires its old traffic counter, and address-only Outgoing rules exclude download totals.
- CSV export snapshots visible rows and columns before opening the Save dialog.
- Packet publication rechecks pause/capture state and current thresholds. Auto-Block uses the triggering packet's endpoint/direction, rechecks current policies and settings, retains cleanup ownership across rapid disable/re-enable, and rolls back decisions cancelled during native changes. Worker-driven dialog dismissal is queued to Tk.

# 3.2

- Global rules can apply to one executable, a group of full executable paths, or all processes. Connection-based editing preserves executable groups; native verification, rollback, removal, and packet accounting respect that scope.
- Global filters accept comma-separated ports and blank targets/ports, including both fields blank. Allow and Block support Incoming, Outgoing, and Both. Editor overlap checks permit independent incoming/outgoing policies, with distinct native names and legacy-name migration.
- Connection status, colors, and editing follow direction matching and block precedence; a matching global block supplies the color when app and global rules both block. Managed Rules describes program/target/port/protocol filters and exposes full executable paths in details/search. Status columns are wider.
- Live Monitor sorts IPv4/IPv6 addresses numerically. All three tables support Ctrl+C for visible selected values in display order and add-rule menus on empty space. Global menus expose six directional actions; Monitor and Alerts have contextual clear actions. Improved light-theme contrast for menu text and the wallet heading.
- Rule export format advanced from 6 to 7: singleton executable scope uses `exe`, groups use `exes`, and older backups still import. Regression checks were consolidated around shared fixtures and global-rule/installation suites.

# 3.1

- Network process usage is now connection / global rule specific (very useful).
- Fixed labels and re-ordered some options added some buttons.
- Added more colums to describe rules better (managed rules section).

# 3.0

- New **Keep Notification in Foreground** setting for Auto-Block prompts.
- Global rules now support multiple/ranges of domains/IPs, local or remote ports, TCP/UDP, and Allow, Block, or Block Incoming actions.
- Double-click a connection, alert, or managed rule to edit the effective app/global rule. Connections with no rule let you choose app or global.
- Context menus now expose the displayed status and every matching managed policy. Rule details include resolved global addresses.
- Saves and restores window size, position, maximized state, and table column widths.
- Second launches now restore/foreground the existing instance instead of showing an already-running dialog.
- Pop up / prompts now appear near area they were triggered from (mouse).
- Global-rule creation is now one editor.
- Removed Active tab section
- Added blue Add Rule before Block Selected. It offers App Rule or Global Rule and prompts for an executable when no process is selected.
- Added orange Block (in) Selected between Block Selected and Allow Selected.
- Fixed cursor color for text input while in dark theme mode.
- Added port and protcols to managed rules section
- Windows Firewall Button now opens Advanced Firewall Settings.
