"""Shared themed widgets, button feedback, table layout and selection behavior."""

import tkinter as tk
from tkinter import font as tkfont, messagebox, ttk

from constants import GLOBAL_PURPLE, GLOBAL_TEAL, GLOBAL_YELLOW

class ThemedContextMenu:
    """Borderless popup with a one-pixel theme border, including on Windows."""

    def __init__(self, root, colors):
        self.root, self.colors = root, colors
        self.window = tk.Toplevel(root, bg=colors['head'], bd=0, highlightthickness=0)
        self.window.withdraw()
        self.window.overrideredirect(True)
        self.body = tk.Frame(self.window, bg=colors['sub'], bd=0, highlightthickness=0)
        self.body.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        self.items = []
        self.active = -1
        self.previous_focus = None
        self.root_bindings = []
        self.window.bind('<Escape>', self._close)
        self.window.bind('<FocusOut>', self._close)
        self.window.bind('<ButtonPress-1>', self._outside_click)
        self.window.bind('<ButtonPress-3>', self._outside_click)
        self.window.bind('<Up>', lambda _: self._move(-1))
        self.window.bind('<Down>', lambda _: self._move(1))
        self.window.bind('<Home>', lambda _: self._select(0))
        self.window.bind('<End>', lambda _: self._select(len(self.items) - 1))
        self.window.bind('<Return>', self._invoke)
        self.window.bind('<space>', self._invoke)

    def add_command(self, label, command, foreground=None, activeforeground='#ffffff'):
        color = foreground or self.colors['fg']
        widget = tk.Label(self.body, text=label, anchor='w', bg=self.colors['sub'],
                          fg=color, font=('Segoe UI', 9), padx=12, pady=5, bd=0)
        widget.pack(fill=tk.X)
        index = len(self.items)
        self.items.append((widget, command, color, activeforeground))
        widget.bind('<Enter>', lambda _: self._select(index))
        widget.bind('<ButtonRelease-1>', lambda _: self._invoke(index=index))

    def add_separator(self):
        tk.Frame(self.body, height=1, bg=self.colors['head'], bd=0,
                 highlightthickness=0).pack(fill=tk.X, padx=6, pady=4)

    def _select(self, index):
        if not self.items:
            return 'break'
        if self.active >= 0:
            widget, _, color, _ = self.items[self.active]
            widget.configure(bg=self.colors['sub'], fg=color)
        self.active = index % len(self.items)
        widget, _, _, color = self.items[self.active]
        widget.configure(bg=self.colors['select'], fg=color)
        return 'break'

    def _move(self, step):
        return self._select((0 if step > 0 else len(self.items) - 1)
                            if self.active < 0 else self.active + step)

    def _invoke(self, event=None, index=None):
        index = self.active if index is None else index
        if 0 <= index < len(self.items):
            command = self.items[index][1]
            self._close()
            command()
        return 'break'

    def _outside_click(self, event):
        x, y = self.window.winfo_rootx(), self.window.winfo_rooty()
        if not (x <= event.x_root < x + self.window.winfo_width() and
                y <= event.y_root < y + self.window.winfo_height()):
            return self._close()

    def _close(self, event=None):
        for sequence, binding in self.root_bindings:
            self.root.unbind(sequence, binding)
        self.root_bindings.clear()
        if self.window.winfo_exists():
            self.window.destroy()
            if event is None and self.previous_focus is not None:
                try:
                    self.previous_focus.focus_set()
                except tk.TclError:
                    pass
        return 'break'

    def post(self, x, y):
        self.previous_focus = self.root.focus_get()
        self.window.update_idletasks()
        width, height = self.window.winfo_reqwidth(), self.window.winfo_reqheight()
        x = max(0, min(x, self.window.winfo_screenwidth() - width))
        y = max(0, min(y, self.window.winfo_screenheight() - height))
        self.window.geometry(f'+{x}+{y}')
        self.window.deiconify()
        self.window.lift()
        self.window.focus_force()
        # A Tk grab captures Windows non-client clicks (including caption buttons).
        # Dismiss on outside input instead, without consuming the original event.
        for sequence in ('<ButtonPress-1>', '<ButtonPress-3>', '<Unmap>', '<Configure>'):
            binding = self.root.bind(sequence, self._dismiss_from_root, add='+')
            self.root_bindings.append((sequence, binding))

    def _dismiss_from_root(self, event):
        if event.type in (tk.EventType.ButtonPress,) or event.widget == self.root:
            self._close(event)


class ToolTip:

    def __init__(self, widget, text, delay=400):
        self.widget, self.text, self.delay = (widget, text, delay)
        self.tip = None
        self.after_id = None
        widget.bind('<Enter>', self._enter, add='+')
        widget.bind('<Leave>', self._leave, add='+')
        widget.bind('<ButtonPress>', self._leave, add='+')
        widget.bind('<Destroy>', self._leave, add='+')

    def _enter(self, _=None):
        self._cancel()
        self.after_id = self.widget.after(self.delay, self._show)

    def _leave(self, _=None):
        self._cancel()
        if self.tip:
            try:
                self.tip.destroy()
            except tk.TclError:
                pass
            self.tip = None

    def _cancel(self):
        if self.after_id:
            try:
                self.widget.after_cancel(self.after_id)
            except tk.TclError:
                pass
            self.after_id = None

    def _show(self):
        text = self.text() if callable(self.text) else self.text
        if self.tip or not str(text or '').strip():
            return
        try:
            # Use the pointer's current position after the hover delay, even if
            # it moved within a wide control. Leave a little room for the cursor.
            x, y = self.widget.winfo_pointerxy()
            x += 12
            y += 18
            tip = tk.Toplevel(self.widget)
            tip.wm_overrideredirect(True)
            tip.wm_geometry(f'+{x}+{y}')
            tip.configure(bg='#2b2b2b')
            tk.Label(tip, text=str(text), justify=tk.LEFT, bg='#2b2b2b', fg='#f0f0f0', relief='solid', borderwidth=1, font=('Segoe UI', 9), padx=8, pady=4).pack(ipadx=1)
            self.tip = tip
        except tk.TclError:
            pass


def add_tooltip(widget, text, delay=400):
    widget._tooltip = ToolTip(widget, text, delay)
    return widget._tooltip
BUTTON_TIPS = {'Block Selected': 'Choose how to block the selected application.', 'Allow Selected': 'Allow all traffic for the selected application.', 'Export CSV': 'Export the visible connection rows to a CSV file.', 'Clear List': 'Clear the Live Monitor connection list.', 'Refresh Rules': 'Refresh the Managed Rules list from Windows Firewall.', 'Add App Rule': 'Create an inbound or outbound application rule.', 'Add Global Rule': 'Create a global IP/domain or local/remote port rule.', 'Remove Selected': 'Remove the selected managed firewall rule(s).', 'Remove Selected Rule': 'Remove the selected managed firewall rule(s).', 'Export Rules': 'Export managed rules to a JSON backup.', 'Import Rules': 'Import and apply managed rules from a JSON file.', 'Windows Firewall': 'Open Windows Defender Firewall.', 'Clear Alerts': 'Clear all entries from the Alerts list.', 'Apply Settings': 'Save and apply the monitoring thresholds and options.', 'Reset to Defaults': 'Reset saved settings and remove PyFirewall-managed rules.'}


class WidgetsMixin:
    """Methods composed into FirewallMonitorApp; state is owned by that application."""

    # Theme application

    def apply_theme(self):
        dark = self.dark_mode_var.get()
        self.dark_mode = bool(dark)
        self.colors = {'bg': '#181818' if dark else '#f2f2f2', 'frame': '#1e1e1e' if dark else '#f2f2f2', 'sub': '#242424' if dark else '#ffffff', 'fg': '#e8e8e8' if dark else '#333333', 'muted': '#a8a8a8' if dark else '#757575', 'entry': '#252526' if dark else '#ffffff', 'select': '#3b78c8' if dark else '#0078D7', 'head': '#2d2d30' if dark else '#e0e0e0', 'even': '#252526' if dark else '#f9f9f9', 'odd': '#1e1e1e' if dark else '#ffffff', 'blocked': '#8b1e1e' if dark else '#ffcaca', 'blocked_in': '#7a4b11' if dark else '#ffcc99', 'global_block': '#381b4b' if dark else '#eadcf4', 'global_allow': '#17665f' if dark else '#c3eee7', 'global_block_in': '#71630f' if dark else '#fff1a8', 'allowed': '#294f31' if dark else '#cce8d2', 'watch': '#5b4a16' if dark else '#fff3cd'}
        self.colors['global_rule_button'] = '#704090'
        self.colors['wallet'] = '#bdbdbd'
        self.root.configure(bg=self.colors['bg'])
        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass
        style.configure('TFrame', background=self.colors['frame'])
        style.configure('TLabel', background=self.colors['frame'], foreground=self.colors['fg'])
        style.configure('TLabelframe', background=self.colors['sub'], foreground=self.colors['fg'], bordercolor=self.colors['blocked_in'])
        style.configure('TLabelframe.Label', background=self.colors['sub'], foreground=self.colors['fg'])
        style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=self.colors['head'], foreground=self.colors['fg'], font=('Segoe UI', 10, 'bold'), padding=[10, 5, 10, 5])
        style.map('TNotebook.Tab', background=[('selected', self.colors['frame']), ('active', self.colors['sub'])], foreground=[('selected', self.colors['fg']), ('active', self.colors['fg'])], padding=[('selected', [10, 8, 10, 4]), ('!selected', [10, 5, 10, 5])])
        style.configure('TCheckbutton', background=self.colors['frame'], foreground=self.colors['fg'])
        style.map('TCheckbutton', background=[('active', self.colors['frame'])], foreground=[('disabled', self.colors['muted']), ('active', self.colors['fg'])])
        style.configure('Treeview', background=self.colors['sub'], foreground=self.colors['fg'] if dark else '#000000', fieldbackground=self.colors['sub'], rowheight=25)
        style.configure('Treeview.Heading', background=self.colors['head'], foreground=self.colors['fg'], font=('Segoe UI', 9, 'bold'))
        style.map('Treeview.Heading', background=[('active', '#d8d8d8'), ('pressed', '#c8c8c8')], foreground=[('active', '#000000'), ('pressed', '#000000')])
        style.map('Treeview', background=[('selected', self.colors['select'])], foreground=[('selected', '#ffffff')])
        style.configure('TEntry', fieldbackground=self.colors['entry'], foreground=self.colors['fg'])
        style.map('TEntry', fieldbackground=[('disabled', self.colors['head'])], foreground=[('disabled', self.colors['muted'])])

        def repaint(parent):
            for widget in parent.winfo_children():
                try:
                    if isinstance(widget, tk.Toplevel) and getattr(widget, '_crypto_dialog', False):
                        self._theme_dialog(widget)
                    elif isinstance(widget, tk.LabelFrame):
                        widget.configure(bg=self.colors['frame'], fg=self.colors['fg'])
                    elif isinstance(widget, tk.Frame):
                        widget.configure(bg='#555555' if getattr(widget, '_button_border_frame', False) else self.colors['frame'])
                    elif isinstance(widget, tk.Label):
                        widget.configure(bg=self.colors['frame'], fg=self.colors[getattr(widget, '_theme_foreground_key', 'fg')])
                    elif isinstance(widget, tk.Entry):
                        widget.configure(bg=self.colors['entry'], fg=self.colors['fg'], insertbackground=self.colors['fg'])
                    elif isinstance(widget, tk.Checkbutton):
                        widget.configure(bg=self.colors['frame'], fg=self.colors['fg'], activebackground=self.colors['frame'], activeforeground=self.colors['fg'], selectcolor=self.colors['entry'])
                    elif isinstance(widget, tk.Button) and hasattr(widget, '_pyfirewall_source_bg'):
                        self._apply_button_theme(widget)
                except tk.TclError:
                    pass
                repaint(widget)
        repaint(self.root)
        if hasattr(self, 'settings_canvas'):
            self.settings_canvas.configure(bg=self.colors['frame'])
        self.configure_tags()
        self.update_filter_ui()
        self.update_status()

    def configure_tags(self):
        for name in ('tree', 'active_tree', 'rules_tree', 'alerts_tree'):
            tree = getattr(self, name, None)
            if tree is None:
                continue
            for tag in ('even', 'odd', 'blocked', 'blocked_in', 'global_block', 'global_block_in', 'global_allow', 'allowed', 'watch'):
                tree.tag_configure(tag, background=self.colors[tag], foreground=self.colors['fg'] if self.dark_mode else '#000000')

    def on_theme_changed(self):
        with self.lock:
            self.dark_mode = bool(self.dark_mode_var.get())
        self.save_settings()
        self.apply_theme()

    # Button colors and hover feedback

    @staticmethod
    def _hover_color(color, dark_mode=True):
        try:
            value = str(color).lstrip('#')
            if len(value) != 6:
                return str(color)
            red, green, blue = (int(value[index:index + 2], 16) for index in (0, 2, 4))
            factor = 0.72 if dark_mode else 0.93
            return '#{:02x}{:02x}{:02x}'.format(*(max(0, int(channel * factor))
                                                for channel in (red, green, blue)))
        except (TypeError, ValueError):
            return str(color)

    def _bind_button_hover(self, button, border=None):
        if getattr(button, '_pyfirewall_hover_bound', False):
            return button
        button._pyfirewall_hover_bound = True
        button._pyfirewall_original_highlightthickness = button.cget('highlightthickness')

        def set_normal_state(bg=None, activebackground=None):
            try:
                if bg is not None:
                    button._pyfirewall_base_bg = bg
                if activebackground is not None:
                    button._pyfirewall_base_active_bg = activebackground
                else:
                    button._pyfirewall_base_active_bg = getattr(button, '_pyfirewall_base_bg', button.cget('bg'))
                if border is not None:
                    border._pyfirewall_base_bg = getattr(button, '_pyfirewall_base_bg', border.cget('bg'))
            except tk.TclError:
                pass

        set_normal_state(button.cget('bg'), button.cget('activebackground'))

        def enter(_event=None):
            try:
                if str(button.cget('state')) == str(tk.DISABLED):
                    button.configure(cursor='arrow')
                    return
                normal_bg = getattr(button, '_pyfirewall_base_bg', button.cget('bg'))
                hover = self._hover_color(normal_bg, self.dark_mode)
                button.configure(bg=hover, activebackground=hover, cursor='hand2')
                if border is not None:
                    border.configure(bg=hover if self.dark_mode else '#555555')
            except tk.TclError:
                pass

        def leave(_event=None):
            try:
                normal_bg = getattr(button, '_pyfirewall_base_bg', button.cget('bg'))
                normal_active_bg = getattr(button, '_pyfirewall_base_active_bg', normal_bg)
                button.configure(bg=normal_bg, activebackground=normal_active_bg, cursor='')
                if border is not None:
                    border.configure(bg=normal_bg if self.dark_mode else '#555555')
            except tk.TclError:
                pass

        button.bind('<Enter>', enter, add='+')
        button.bind('<Leave>', leave, add='+')
        button._pyfirewall_set_normal_state = set_normal_state
        self._set_button_colors(button, border, button.cget('bg'), button.cget('fg'),
                                button.cget('state'), activebackground=button.cget('activebackground'))
        return button

    def _set_button_colors(self, button, border, color, fg='white', state=tk.NORMAL, activebackground=None):
        if button is None:
            return
        try:
            # Keep the semantic source colors so theme toggles never repeatedly
            # lighten an already softened background, and dark mode restores it.
            button._pyfirewall_source_bg = color
            button._pyfirewall_source_fg = fg
            button._pyfirewall_source_active_bg = activebackground or color
            button._pyfirewall_border = border
            button.configure(state=state)
            self._apply_button_theme(button)
        except tk.TclError:
            pass

    def _apply_button_theme(self, button):
        try:
            color = button._pyfirewall_source_bg
            active = button._pyfirewall_source_active_bg
            fg = '#ffffff' if self.dark_mode else '#000000'
            border = button._pyfirewall_border
            dark_color_key = getattr(button, '_pyfirewall_dark_color_key', None)
            if self.dark_mode and dark_color_key:
                color = active = self.colors[dark_color_key]
            elif self.dark_mode:
                # Derive from the original semantic color on every update so
                # theme switches and state changes never compound the shading.
                channels = button.winfo_rgb(color)
                color = '#{:02x}{:02x}{:02x}'.format(*(
                    round((channel / 257) * 0.75) for channel in channels))
                active = color
            else:
                channels = button.winfo_rgb(color)
                color = '#{:02x}{:02x}{:02x}'.format(*(
                    round((channel / 257) * 0.30 + 255 * 0.70) for channel in channels))
                active = color
            button.configure(bg=color, activebackground=active, fg=fg, activeforeground=fg)
            setter = getattr(button, '_pyfirewall_set_normal_state', None)
            if callable(setter):
                setter(color, active)
            else:
                button._pyfirewall_base_bg = color
                button._pyfirewall_base_active_bg = active
            if border is not None:
                border_color = color if self.dark_mode else '#555555'
                border.configure(bg=border_color)
                border._pyfirewall_base_bg = border_color
            else:
                # Dialog actions have no surrounding frame; use Tk's one-pixel
                # highlight outline, with the same color when keyboard-focused.
                button.configure(highlightthickness=(
                    getattr(button, '_pyfirewall_original_highlightthickness', 0)
                    if self.dark_mode else 1),
                    highlightbackground='#555555', highlightcolor='#555555')
        except tk.TclError:
            pass

    def _button(self, parent, text, command, color=None, pack=True, tooltip=None, dark_color_key=None, **options):
        color = color or '#757575'
        border = tk.Frame(parent, bg=color, bd=0, highlightthickness=0)
        border._button_border_frame = True
        settings = {'text': text, 'command': command, 'bg': color, 'fg': 'white', 'activebackground': color, 'activeforeground': 'white', 'relief': 'flat', 'borderwidth': 0, 'highlightthickness': 0, 'font': ('Segoe UI', 9, 'bold'), 'padx': 9}
        settings.update(options)
        button = tk.Button(border, **settings)
        button._pyfirewall_dark_color_key = dark_color_key
        self._bind_button_hover(button, border)
        button.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        if pack:
            border.pack(side=tk.LEFT, padx=4)
        add_tooltip(button, tooltip or BUTTON_TIPS.get(text, ''))
        return button if pack else border

    # Tree construction and sizing

    def _make_tree(self, parent, columns, widths, order_key):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=columns, show='headings', selectmode='extended')
        tree._column_order_key = order_key
        for column in columns:
            width, anchor, stretch = widths.get(column, (180, tk.W, True))
            tree.heading(column, text=column)
            tree.column(column, width=width, anchor=anchor, stretch=False)
        order = self._normalized_column_order(order_key, columns)
        tree['displaycolumns'] = tuple(c for c in order if c not in self.hidden_columns.get(order_key, [])) or (order[0],)
        horizontal = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        horizontal.grid(row=1, column=0, sticky='ew')
        scrollbar.grid(row=0, column=1, sticky='ns')
        horizontal.grid_remove()
        scrollbar.grid_remove()
        tree.grid(row=0, column=0, sticky='nsew')
        tree._layout_pending = None
        tree._fill_column = None
        tree._horizontal_scrollbar = horizontal
        tree._vertical_scrollbar = scrollbar
        def scroll(bar, first, last):
            bar.set(first, last)
            visible = float(first) > 0.000001 or float(last) < 0.999999
            if visible != bool(bar.winfo_manager()):
                bar.grid() if visible else bar.grid_remove()
            self._schedule_tree_layout(tree)
        tree.configure(xscrollcommand=lambda first, last: scroll(horizontal, first, last),
                       yscrollcommand=lambda first, last: scroll(scrollbar, first, last))
        tree.bind('<Configure>', lambda _: self._schedule_tree_layout(tree), add='+')
        def cancel_layout(event):
            if event.widget == tree and tree._layout_pending is not None:
                tree.after_cancel(tree._layout_pending)
                tree._layout_pending = None
        tree.bind('<Destroy>', cancel_layout, add='+')
        tree.bind('<Control-a>', self.select_all_rows)
        tree.bind('<Control-A>', self.select_all_rows)
        self._bind_tree_headers(tree)
        return tree

    def _schedule_tree_layout(self, tree):
        if tree._layout_pending is None:
            tree._layout_pending = tree.after_idle(lambda: self._fill_tree_column(tree))

    def _fill_tree_column(self, tree):
        tree._layout_pending = None
        columns = tuple(tree['displaycolumns'])
        if not columns or tree.winfo_width() <= 1:
            return
        previous = tree._fill_column
        if previous:
            current = tree.column(previous, 'width')
            # Preserve a manual resize, but discard space added solely to fill.
            if current != tree._fill_width:
                tree._fill_base_width = current
            if previous != columns[-1]:
                tree.column(previous, width=tree._fill_base_width)
        last = columns[-1]
        if previous != last:
            tree._fill_base_width = tree.column(last, 'width')
        border = ttk.Style(tree).lookup(tree.cget('style') or 'Treeview', 'borderwidth') or 1
        # The tree's width already excludes its sibling vertical scrollbar.
        # Leave a small allowance for theme/DPI rounding at the inner borders
        # so filling unused space cannot itself create horizontal overflow.
        available = max(0, tree.winfo_width() - 2 * tree.winfo_pixels(border) - 4)
        preceding = sum(tree.column(c, 'width') for c in columns[:-1])
        width = max(tree._fill_base_width, available - preceding)
        tree._fill_column, tree._fill_width = last, width
        if tree.column(last, 'width') != width:
            tree.column(last, width=width)

    def _normalized_column_order(self, order_key, columns=None):
        default = tuple(self.default_column_orders[order_key])
        available = set(columns or default)
        with self.lock:
            saved = list(self.column_orders.get(order_key, list(default)))
            result = [c for c in saved if c in available]
            result.extend((c for c in default if c in available and c not in result))
            if columns:
                result.extend((c for c in columns if c not in result))
            self.column_orders[order_key] = result
            return list(result)

    # Column visibility, sorting and reordering

    def _tree_column_from_x(self, tree, x):
        try:
            token = tree.identify_column(x)
            if not token.startswith('#'):
                return None
            index = int(token[1:]) - 1
            order = list(tree['displaycolumns'])
            if 0 <= index < len(order):
                return order[index]
        except (ValueError, tk.TclError):
            pass
        return None

    def _bind_tree_headers(self, tree):
        tree.bind('<Button-1>', self._tree_header_press, add='+')
        tree.bind('<B1-Motion>', self._tree_header_motion, add='+')
        tree.bind('<ButtonRelease-1>', self._tree_header_release, add='+')

    def _show_header_menu(self, event, tree):
        if tree.identify_region(event.x, event.y) not in {'heading', 'separator'}:
            return False
        column = self._tree_column_from_x(tree, event.x)
        if column:
            menu = self._context_menu()
            menu.add_command(label='Hide Column', command=lambda: self._hide_column(tree, column))
            menu.add_command(label='Select Columns', command=lambda: self._select_columns(tree))
            menu.post(event.x_root, event.y_root)
        return True

    def _set_visible_columns(self, tree, visible):
        key = tree._column_order_key
        order = self._normalized_column_order(key, tree['columns'])
        selected = [c for c in order if c in visible]
        if not selected:
            messagebox.showinfo('Select Columns', 'Keep at least one column visible.', parent=self.root)
            return False
        with self.lock:
            self.hidden_columns[key] = [c for c in order if c not in selected]
        tree['displaycolumns'] = tuple(selected)
        self.save_settings()
        return True

    def _hide_column(self, tree, column):
        self._set_visible_columns(tree, [c for c in tree['displaycolumns'] if c != column])

    def _select_columns(self, tree):
        dialog = tk.Toplevel(self.root)
        dialog.title('Select Columns')
        dialog.withdraw()
        dialog.transient(self.root)
        self._theme_dialog(dialog)
        body = ttk.Frame(dialog, padding=16)
        body.pack(fill=tk.BOTH, expand=True)
        variables = {}
        for column in self._normalized_column_order(tree._column_order_key, tree['columns']):
            variable = tk.BooleanVar(value=column in tree['displaycolumns'])
            variables[column] = variable
            ttk.Checkbutton(body, text=column, variable=variable).pack(anchor=tk.W, pady=2)
        def apply():
            if self._set_visible_columns(tree, [c for c, v in variables.items() if v.get()]):
                dialog.destroy()
        ttk.Button(body, text='Apply', command=apply).pack(side=tk.LEFT, pady=(12, 0))
        ttk.Button(body, text='Cancel', command=dialog.destroy).pack(side=tk.RIGHT, pady=(12, 0))
        dialog.bind('<Escape>', lambda _: dialog.destroy())
        self._center_dialog(dialog)
        dialog.deiconify()
        self.root.wait_window(dialog)

    def _autosize_header(self, event, tree):
        region = tree.identify_region(event.x, event.y)
        if region not in {'heading', 'separator'}:
            return False
        self.header_drag.pop(str(tree), None)
        if region == 'separator':
            column = self._tree_column_from_x(tree, event.x)
            if column:
                style = ttk.Style(tree)
                heading_font = tkfont.Font(root=tree, font=style.lookup('Treeview.Heading', 'font') or 'TkHeadingFont')
                row_font = tkfont.Font(root=tree, font=style.lookup('Treeview', 'font') or 'TkDefaultFont')
                widths = [heading_font.measure(str(tree.heading(column, 'text'))) + 32]
                def measure(parent=''):
                    for iid in tree.get_children(parent):
                        value = str(tree.set(iid, column))
                        widths.append(max((row_font.measure(line) for line in value.splitlines()), default=0) + 20)
                        measure(iid)
                measure()
                tree.column(column, width=max(widths), stretch=False)
        return True

    def _tree_header_press(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            return
        if tree.identify_region(event.x, event.y) != 'heading':
            return
        column = self._tree_column_from_x(tree, event.x)
        if not column:
            return 'break'
        self.header_drag[str(tree)] = {'column': column, 'start_x': event.x, 'dragging': False}
        tree.focus_set()
        return 'break'

    def _tree_header_motion(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            return
        state = self.header_drag.get(str(tree))
        if not state:
            return
        if abs(event.x - state['start_x']) >= 6:
            state['dragging'] = True
        if state['dragging']:
            tree.configure(cursor='hand2')
        return 'break'

    def _tree_header_release(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            return
        state = self.header_drag.pop(str(tree), None)
        if not state:
            return
        tree.configure(cursor='')
        if not state['dragging']:
            self.sort_tree(tree, state['column'])
            return 'break'
        source = state['column']
        order = list(tree['displaycolumns'])
        if source not in order:
            return 'break'
        target = self._tree_column_from_x(tree, event.x)
        if target and target in order and (target != source):
            source_index = order.index(source)
            target_index = order.index(target)
            order.pop(source_index)
            insert_at = target_index + 1 if target_index > source_index else target_index
            order.insert(insert_at, source)
            tree['displaycolumns'] = tuple(order)
            with self.lock:
                hidden = self.hidden_columns.get(tree._column_order_key, [])
                visible_order = iter(order)
                self.column_orders[tree._column_order_key] = [
                    c if c in hidden else next(visible_order)
                    for c in self.column_orders[tree._column_order_key]]
            self.save_settings()
        return 'break'

    # Mouse selection

    def _bind_tree_selection(self, tree):
        tree.bind('<Button-1>', self._tree_selection_press, add='+')

    def _tree_selection_press(self, event):
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            return
        region = tree.identify_region(event.x, event.y)
        if region in {'heading', 'separator'}:
            return
        children = list(tree.get_children())
        iid = tree.identify_row(event.y)
        started_on_blank = not iid or iid not in children
        if not children:
            return
        last_box = tree.bbox(children[-1])
        started_below_rows = bool(started_on_blank and last_box and (event.y >= last_box[1] + last_box[3]))
        if started_below_rows:
            tree.selection_remove(tree.selection())
            self.selection_anchors.pop(str(tree), None)
        if started_on_blank:
            return 'break' if started_below_rows else None
        anchor = self.selection_anchors.get(str(tree))
        shift = bool(event.state & 1)
        control = bool(event.state & 4)
        if shift and anchor in children:
            start = children.index(anchor)
            end = children.index(iid)
            lo, hi = sorted((start, end))
            range_iids = children[lo:hi + 1]
            if control:
                tree.selection_add(range_iids)
            else:
                tree.selection_set(range_iids)
        elif control:
            if iid in tree.selection():
                tree.selection_remove(iid)
            else:
                tree.selection_add(iid)
        else:
            tree.selection_set(iid)
        try:
            tree.focus_force()
        except tk.TclError:
            tree.focus_set()
        tree.focus(iid)
        self.selection_anchors[str(tree)] = iid
        return 'break'

    def _remember_selection_anchor(self, tree, iid):
        if iid and tree.exists(iid):
            self.selection_anchors[str(tree)] = iid

    def select_all_rows(self, event=None):
        tree = event.widget if event else None
        if isinstance(tree, ttk.Treeview):
            try:
                tree.focus_force()
            except tk.TclError:
                tree.focus_set()
            tree.selection_set(tree.get_children())
            children = tree.get_children()
            if children:
                self._remember_selection_anchor(tree, children[0])
            return 'break'

    # Menu and dialog presentation

    def _context_menu(self):
        return ThemedContextMenu(self.root, self.colors)

    def _menu_rule_command(self, menu, label, command, rule_tag):
        rule_colors = {'allowed': '#4CAF50', 'blocked': '#f44336', 'blocked_in': '#ff9800', 'global_allow': GLOBAL_TEAL, 'global_block': GLOBAL_PURPLE, 'global_block_in': GLOBAL_YELLOW}
        if not self.dark_mode:
            # Keep the same semantic hues with stronger contrast on white menus.
            rule_colors.update(allowed='#26732b', blocked='#c62828', blocked_in='#995900',
                               global_allow='#17665f', global_block='#7040a0', global_block_in='#776400')
        color = rule_colors.get(rule_tag, self.colors['fg'])
        menu.add_command(label=label, command=command, foreground=color, activeforeground='#ffffff')

    def _center_dialog(self, dialog, width=None, height=None):
        dialog.update_idletasks()
        width = max(1, int(width or dialog.winfo_reqwidth()))
        height = max(1, int(height or dialog.winfo_reqheight()))
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        x = max(0, (screen_width - width) // 2)
        y = max(0, (screen_height - height) // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')

    def _theme_dialog(self, dialog):
        dialog.configure(bg=self.colors['frame'])

    def _show_details_dialog(self, title, text, tooltip):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.resizable(False, False)
        dialog.withdraw()
        dialog.transient(self.root)
        self._theme_dialog(dialog)
        body = tk.Frame(dialog, bg=self.colors['frame'])
        body.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        label = tk.Label(body, text=text, justify=tk.LEFT, anchor=tk.NW, bg=self.colors['frame'], fg=self.colors['fg'], font=('Segoe UI', 10), padx=14, pady=12)
        label.pack(fill=tk.X)
        button = tk.Button(body, text='Close', command=dialog.destroy, bg=self.colors.get('button', '#757575'), fg='#ffffff', activebackground=self.colors.get('head', '#2d2d30'), activeforeground='#ffffff', relief='flat', font=('Segoe UI', 9, 'bold'), padx=12, pady=4)
        self._bind_button_hover(button)
        button.pack(pady=(2, 8))
        add_tooltip(button, tooltip)
        dialog.protocol('WM_DELETE_WINDOW', dialog.destroy)
        dialog.update_idletasks()
        max_width = max(520, int(dialog.winfo_screenwidth() * 0.85))
        requested_width = dialog.winfo_reqwidth()
        target_width = min(max(requested_width, 650), max_width)
        if requested_width > max_width:
            label.configure(wraplength=max_width - 60)
            dialog.update_idletasks()
            target_width = max_width
        self._center_dialog(dialog, target_width, dialog.winfo_reqheight())
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()
