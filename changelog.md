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