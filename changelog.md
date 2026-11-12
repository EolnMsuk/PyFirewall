# 4.2

* **Upgrade Required:** Before installing 4.2, remove all previous **PyFirewall-managed** Windows Firewall rules, close PyFirewall normally and wait for cleanup to finish, then delete the existing `firewall_config.json`. Keep recovery journals and installation ownership files. Backups using older rule formats cannot be imported; create fresh rules in 4.2.
* **Auto-Block Tooltips:** Keep every action tooltip above its owner, including live foreground-preference changes, without taking focus or changing prompt behavior.
* **Text Undo:** Ctrl+Z undoes typing, paste, cut, and deletion separately in each search, global-rule, settings, and legacy target input. Saves and firewall/application actions are outside text history.
* **Remote Port Rules:** Add and Edit Global Rule place the TCP/UDP selector beside **Remote Port / Protocol:**. Global rules always leave local ports unrestricted, and Managed Rules no longer has a Local Port column.
* **Global Rule Groups:** Manual creation, editing, import, and Auto-Block connection decisions combine targets only when executable scope, the complete normalized remote-port selection, protocol, action, and direction match. Explicit multi-port rules remain supported. Native rules retain separate executable, protocol, and direction instances, with verified replacement and rollback.
* **Connection Groups:** Live Monitor and Alerts require consecutive arrivals with the same process name, PID, executable, remote IP, protocol, remote port, and direction. Equal local ports remain visible; differing ports show a dash. Show/Copy Connection Details lists every distinct member local port. Alerts now includes Local Port, Download, and Upload columns. Raw flows, arrival boundaries, every alert event, and unique-flow traffic totals are retained.
* **Connection Rule Editing:** Visibly prefill the observed IP and associated domain. Connection edits and removals isolate their targets, splitting IPv4/IPv6 subnets, ranges, and all-address coverage while preserving the remainder. Multiple selections apply together after review, preserving shared-IP selections and distinct connection filters. Managed Rules still edits/removes whole groups. Verified transactions preserve rollback, stale-edit checks, and save retries; split traffic history is retained once.
* **Clean Rule Format:** Global rules use one representation for executable lists, targets with their own saved resolved addresses, and remote-port lists. Configuration uses schema marker `4.1`, and managed-rule backups use format version 8. Old and mixed formats are rejected before native rule changes; legacy rule conversion and native-name compatibility paths were removed.

# 4.0

* **Rule Editors & Search:** Shortened Add/Edit Global Rule help and added right-click Copy/Paste to domain/IP and port inputs and the Live Monitor, Managed Rules, and Alerts search fields.
* **Settings Links:** Reordered support links to PyFirewall GitHub, Donate via Venmo, then Donate via Crypto.
* **Capture Status:** Moved capture-adapter status to Settings above Monitor & Filter, with wrapping for long adapter and operation names.
* **Alerts Layout:** Removed the dropped-alert/untracked-rate capacity-status line while retaining the internal counters and capacity protections.
* **Connection Decisions:** Added Block Connection and Allow Connection to Auto-Block Protection. These create rules for the executable, exact remote IP, remote port, and captured protocol in both directions, leaving the local port unrestricted. Verification, save retries, and owned temporary-hold cleanup complete before the prompt closes.
* **Retained Hostnames:** Kept learned names visible for retained connections and alerts, backfilled quiet records after DNS discovery, and avoided repeat lookups for records already displaying a name.

# 3.5

* **Label Changes:** Modifed some labels / system tray elements.
* **Documentation:** Updated documentation / simplified changelog for previous masssive update.
* **EOL:** This project is complete / EOL, I plan to only issue bug fixes if issues are reported.

# 3.4

* **Smoother Updates & Shutdown:** Setup and uninstall now close the app cleanly instead of abruptly stopping background processes, and recovery journals are preserved.
* **Auto-Block Fixes:** Fixed issues where failed settings saves could get lost, and invalid threshold numbers are now properly caught and blocked before causing errors.
* **Better Task Handling:** Windows login tasks now request unlimited execution time correctly without messing up your other startup settings.

# 3.3

* **Better Tray Icon Controls:** Clicking the tray icon once now properly restores and brings the main window to the front (preserving its maximized state and position).
* **New Traffic Columns:** Live Monitor and Managed Rules now include **Download** and **Upload** columns, complete with column choosers and numeric sorting.
* **Reliable CSV Export:** Exporting to CSV now correctly captures your currently visible rows and columns before opening the save dialog.

# 3.2

* **Flexible Global Rules:** Global rules can now apply to a single executable, a group of file paths, or all processes.
* **Easier Port & Filter Editing:** Global filters now accept comma-separated ports and blank targets/ports, supporting Incoming, Outgoing, and Both directions.
* Live Monitor now sorts IPv4 and IPv6 addresses numerically.
* You can now use **Ctrl+C** to copy visible selected values across tables.
* Improved light-theme contrast for menu text.


# 3.1

* **Per-Connection Usage:** Network process usage is now specific to individual connections and global rules.
* **Better Rule Details:** Added more descriptive columns to the Managed Rules section, along with general label and button layout improvements.


# 3.0

* **Keep Notification Foreground:** Added a new setting to keep Auto-Block prompt notifications in the foreground.
* **Enhanced Global Rules:** Global rules now support multiple domains/IPs, port ranges, TCP/UDP, and new actions (Allow, Block, Block Incoming).
* **Quick Editing:** Double-click any connection, alert, or managed rule to instantly edit its effective rule.
* **Smart Window Memory:** The app now saves and restores your window size, position, maximized state, and table column widths.
* **Better Multi-Launching:** Trying to open a second instance of the app will now just restore and bring the existing window to the front instead of showing an error.
* **Popups Follow the Mouse:** Prompts and popups now appear near the area where they were triggered.
