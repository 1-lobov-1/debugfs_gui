#!/usr/bin/env python3
# debugfs_gui_full.py
# GUI wrapper for debugfs: protected mode + interactive forms

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinter.simpledialog
import subprocess
import shutil
import threading
import os
import re
import datetime

class DebugFSGui:
    """GUI-обёртка для утилиты debugfs.

    Особенности:
    - Защита от опасных операций: Safe Mode (по умолчанию ON).
    - Требуется ввод CONFIRM для выполнения опасных команд.
    - Интерактивные формы (stat, ncheck, icheck, dump, readblock, write, mkdir, rm, set_inode).
    - Дерево файловой системы (ls -l) с двойным кликом -> stat.
    - Логирование в debugfs_gui.log.
    """

    # Ключевые слова, считающиеся потенциально изменяющими ФС
    DESTRUCTIVE_KEYWORDS = [
        'write', 'rm', 'unlink', 'clri', 'set_inode', 'ln', 'mknod', 'rmdir', 'creat',
        'truncate', 'mkfs', 'chattr', 'zeroed', 'set_acl', 'link'
    ]

    def __init__(self, root):
        self.root = root
        self.root.title("DebugFS GUI — Protected Mode")
        self.root.geometry("1200x820")
        self.device_path = tk.StringVar()
        self.use_sudo = tk.BooleanVar(value=True)
        self.safe_mode = tk.BooleanVar(value=True)  # Safe mode blocks destructive commands
        self.command_history = []
        self.current_directory = "/"
        self.fs_info = {}
        self.log_path = os.path.join(os.getcwd(), "debugfs_gui.log")
        self.create_widgets()
        self.check_installation()

    def check_installation(self):
        """Проверка наличия утилиты debugfs."""
        if shutil.which("debugfs") is None:
            messagebox.showerror("Ошибка", "Утилита debugfs не найдена! Установите пакет e2fsprogs.")
            self.root.destroy()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # --- Вкладка Команды ---
        self.command_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.command_frame, text="Команды")

        top_frame = ttk.LabelFrame(self.command_frame, text="Настройки подключения", padding=8)
        top_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(top_frame, text="Устройство/Образ:").pack(side="left")
        self.dev_entry = ttk.Entry(top_frame, textvariable=self.device_path, width=60)
        self.dev_entry.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(top_frame, text="Обзор...", command=self.browse_file).pack(side="left", padx=5)
        ttk.Checkbutton(top_frame, text="Использовать sudo", variable=self.use_sudo).pack(side="left", padx=5)
        ttk.Checkbutton(top_frame, text="Режим: только чтение (Safe)", variable=self.safe_mode).pack(side="left", padx=10)
        ttk.Button(top_frame, text="Получить инфо FS", command=self.get_fs_info).pack(side="left", padx=5)

        info_frame = ttk.LabelFrame(self.command_frame, text="Информация о ФС", padding=8)
        info_frame.pack(fill="x", padx=10, pady=5)
        self.fs_info_label = ttk.Label(info_frame, text="Файловая система: не выбрана", foreground="blue")
        self.fs_info_label.pack(anchor="w")

        nav_frame = ttk.LabelFrame(self.command_frame, text="Навигация", padding=8)
        nav_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(nav_frame, text="Текущий путь:").pack(side="left")
        self.path_label = ttk.Label(nav_frame, text=self.current_directory, foreground="blue")
        self.path_label.pack(side="left", padx=(5, 10))
        ttk.Button(nav_frame, text="cd", command=lambda: self.open_interactive("cd")).pack(side="left", padx=3)
        ttk.Button(nav_frame, text="pwd", command=lambda: self.run_custom_command("pwd")).pack(side="left", padx=3)
        ttk.Button(nav_frame, text="Обновить", command=self.refresh_directory).pack(side="left", padx=3)

        cmd_frame = ttk.LabelFrame(self.command_frame, text="Ввод команды", padding=8)
        cmd_frame.pack(fill="x", padx=10, pady=5)
        self.cmd_entry = ttk.Combobox(cmd_frame, values=self._default_commands(), width=80)
        self.cmd_entry.set("ls -l")
        self.cmd_entry.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(cmd_frame, text="Выполнить", command=self.run_command).pack(side="left", padx=5)
        ttk.Button(cmd_frame, text="Формы...", command=self.open_forms_menu).pack(side="left", padx=5)

        hist_frame = ttk.LabelFrame(self.command_frame, text="История команд", padding=8)
        hist_frame.pack(fill="x", padx=10, pady=5)
        self.history_listbox = tk.Listbox(hist_frame, height=4)
        self.history_listbox.pack(side="left", fill="x", expand=True, padx=5)
        self.history_listbox.bind("<Double-Button-1>", self.load_command_from_history)

        out_frame = ttk.LabelFrame(self.command_frame, text="Вывод (stdout/stderr)", padding=8)
        out_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.output_text = tk.Text(out_frame, wrap="word", font=("Courier", 10), bg="#111111", fg="#ddeeff")
        scrollbar = ttk.Scrollbar(out_frame, command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.output_text.pack(side="left", fill="both", expand=True)

        # --- Вкладка ФС (tree view) ---
        self.fs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.fs_frame, text="Файловая система")
        tree_frame = ttk.LabelFrame(self.fs_frame, text="Содержимое", padding=8)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.tree = ttk.Treeview(tree_frame)
        self.tree["columns"] = ("inode", "type", "size", "perms", "links", "uid", "gid", "mtime")
        self.tree.column("#0", width=260)
        for col in self.tree["columns"]:
            self.tree.column(col, width=90, anchor=tk.CENTER)
        self.tree.heading("#0", text="Имя")
        self.tree.heading("inode", text="Inode")
        self.tree.heading("type", text="Тип")
        self.tree.heading("size", text="Размер")
        self.tree.heading("perms", text="Права")
        self.tree.heading("links", text="Links")
        self.tree.heading("uid", text="UID")
        self.tree.heading("gid", text="GID")
        self.tree.heading("mtime", text="Дата")

        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.bind("<Double-1>", self.on_tree_double_click)

        ttk.Button(self.fs_frame, text="Загрузить/Обновить", command=self.populate_tree).pack(pady=6)

        # --- Вкладка Тестовые сценарии ---
        self.test_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.test_frame, text="Тестовые сценарии")
        self.create_test_scenarios_tab()

        self.status_bar = ttk.Label(self.root, text="Готов", relief=tk.SUNKEN, anchor="w")
        self.status_bar.pack(side="bottom", fill="x")

        self.root.bind("<Return>", lambda e: self.run_command())

    def _default_commands(self):
        return [
            "ls -l", "stat <inode>", "ncheck <inode>", "icheck <block>", "stats",
            "dump <inode> <outfile>", "rdump / <dest_dir>"
        ]

    def browse_file(self):
        filename = filedialog.askopenfilename(title="Выберите образ диска или устройство")
        if filename:
            self.device_path.set(filename)
            self.get_fs_info()

    def log(self, text):
        """Логирование в файл с обработкой ошибок."""
        try:
            ts = datetime.datetime.now().isoformat()
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"{ts} {text}\n")
        except (IOError, OSError) as e:
            # Тихая обработка ошибок логирования, чтобы не прерывать работу приложения
            pass

    def get_fs_info(self):
        device = self.device_path.get().strip()
        if not device:
            return
        self.status_bar.config(text="Получение информации о ФС...")
        self.root.update_idletasks()
        cmd = "stats"
        args = self._build_cmd_args()
        input_data = f"{cmd}\nquit\n"
        try:
            proc = subprocess.run(args, input=input_data, capture_output=True, text=True, timeout=12)
            if proc.returncode == 0:
                out = proc.stdout
                fs_type = "ext?" if "Filesystem magic number" in out else "unknown"
                m = re.search(r"Filesystem size:\s*(\d+)", out)
                size = m.group(1) if m else "unknown"
                self.fs_info = {"type": fs_type, "size_blocks": size}
                self.fs_info_label.config(text=f"Файловая система: {fs_type}, Размер: {size} блоков")
                self.log(f"INFO: stats on {device}: size={size}")
            else:
                self.fs_info_label.config(text="Ошибка: не удалось получить информацию о ФС")
                self.log(f"ERROR: stats failed: {proc.stderr}")
        except Exception as e:
            self.fs_info_label.config(text=f"Ошибка: {e}")
            self.log(f"EXCEPT: {e}")
        finally:
            self.status_bar.config(text="Готов")

    def _build_cmd_args(self):
        """Построение аргументов команды для subprocess."""
        args = []
        if self.use_sudo.get():
            # Используем sudo без -S, так как пароль не передается через stdin
            # Пользователь должен настроить sudo без пароля для debugfs или вводить пароль вручную
            args.append("sudo")
        args.extend(["debugfs", self.device_path.get().strip()])
        return args
    
    def _validate_device(self):
        """Проверка наличия устройства. Возвращает True если устройство указано."""
        device = self.device_path.get().strip()
        if not device:
            messagebox.showwarning("Внимание", "Укажите устройство или образ!")
            return False
        return True

    def run_command(self):
        """Выполнение команды из поля ввода."""
        if not self._validate_device():
            return
        command = self.cmd_entry.get().strip()
        if not command:
            messagebox.showwarning("Внимание", "Введите команду!")
            return
        if command not in self.command_history:
            self.command_history.append(command)
            self.history_listbox.insert(tk.END, command)
            if len(self.command_history) > 200:
                self.command_history.pop(0)
                self.history_listbox.delete(0)
        if self._is_destructive(command):
            if self.safe_mode.get():
                messagebox.showerror("Операция заблокирована", "Режим Safe включён — запрещено изменять ФС.")
                return
            if not self.confirm_destructive(command):
                return
        self.execute_debugfs_command(command)

    def run_custom_command(self, command):
        """Выполнение пользовательской команды с проверкой безопасности."""
        if not self._validate_device():
            return
        if self._is_destructive(command) and self.safe_mode.get():
            messagebox.showerror("Операция заблокирована", "Режим Safe включён — запрещено изменять ФС.")
            return
        self.execute_debugfs_command(command)

    def _is_destructive(self, command):
        lc = command.lower()
        for kw in self.DESTRUCTIVE_KEYWORDS:
            if kw in lc:
                return True
        return False

    def confirm_destructive(self, command):
        """Запрос подтверждения для опасных операций."""
        txt = (f"Вы пытаетесь выполнить опасную команду:\n\n{command}\n\n"
               "Это изменит файловую систему. Введите слово CONFIRM, чтобы продолжить.")
        ans = tk.simpledialog.askstring("Подтверждение опасной операции", txt)
        if ans == "CONFIRM":
            self.log(f"CONFIRMED destructive command: {command}")
            return True
        else:
            self.log(f"CANCELLED destructive command: {command}")
            return False

    def execute_debugfs_command(self, command):
        self.output_text.delete(1.0, tk.END)
        self.status_bar.config(text="Выполнение команды...")
        args = self._build_cmd_args()
        input_data = command + "\nquit\n"
        thread = threading.Thread(target=self._run_subproc_thread, args=(args, input_data, command))
        thread.daemon = True
        thread.start()

    def _run_subproc_thread(self, args, input_data, command):
        """Выполнение команды в отдельном потоке."""
        try:
            proc = subprocess.run(args, input=input_data, capture_output=True, text=True, timeout=60)
            self.root.after(0, self._display_process_result, proc, command)
        except subprocess.TimeoutExpired:
            self.root.after(0, lambda: (
                self.output_text.insert(tk.END, "\nТаймаут выполнения\n"),
                self.status_bar.config(text="Таймаут")
            ))
            self.log(f"TIMEOUT: {command}")
        except Exception as e:
            self.root.after(0, lambda: (
                self.output_text.insert(tk.END, f"Ошибка: {e}\n"),
                self.status_bar.config(text="Ошибка")
            ))
            self.log(f"EXCEPTION in thread: {e}")

    def _display_process_result(self, proc, command):
        """Отображение результата выполнения команды."""
        out = proc.stdout.replace("debugfs:", "")
        self.output_text.insert(tk.END, f"> {command}\n")
        self.output_text.insert(tk.END, "=" * 60 + "\n")
        if out.strip():
            self.output_text.insert(tk.END, out)
        if proc.stderr:
            self.output_text.insert(tk.END, "\n[STDERR]:\n")
            self.output_text.insert(tk.END, proc.stderr)
        self.log(f"CMD: {command} -> rc={proc.returncode}")
        # Обновление текущей директории при выполнении pwd
        if command.strip().lower() == "pwd":
            for line in out.splitlines():
                if line.startswith("/"):
                    self.current_directory = line.strip()
                    self.path_label.config(text=self.current_directory)
                    break
        self.status_bar.config(text="Готов")

    def load_command_from_history(self, event):
        sel = self.history_listbox.curselection()
        if sel:
            cmd = self.command_history[sel[0]]
            self.cmd_entry.set(cmd)

    def refresh_directory(self):
        self.run_custom_command("pwd")

    def populate_tree(self):
        """Загрузка дерева файловой системы."""
        if not self._validate_device():
            return
        self.status_bar.config(text="Загрузка дерева...")
        self.tree.delete(*self.tree.get_children())
        cmd = f"ls -l {self.current_directory}" if self.current_directory else "ls -l /"
        args = self._build_cmd_args()
        input_data = f"{cmd}\nquit\n"
        thread = threading.Thread(target=self._run_subproc_for_tree, args=(args, input_data))
        thread.daemon = True
        thread.start()

    def _run_subproc_for_tree(self, args, input_data):
        """Выполнение команды ls для построения дерева в отдельном потоке."""
        try:
            proc = subprocess.run(args, input=input_data, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                self.root.after(0, lambda: self._parse_ls_output(proc.stdout))
            else:
                error_msg = f"Ошибка загрузки дерева:\n{proc.stderr}\n"
                self.root.after(0, lambda: (
                    self.output_text.insert(tk.END, error_msg),
                    self.status_bar.config(text="Ошибка")
                ))
                self.log(f"ERROR loading tree: {proc.stderr}")
        except subprocess.TimeoutExpired:
            self.root.after(0, lambda: (
                self.output_text.insert(tk.END, "Таймаут при загрузке дерева\n"),
                self.status_bar.config(text="Таймаут")
            ))
        except Exception as e:
            self.root.after(0, lambda: (
                self.output_text.insert(tk.END, f"Ошибка: {e}\n"),
                self.status_bar.config(text="Ошибка")
            ))
            self.log(f"EXCEPTION loading tree: {e}")

    def _parse_ls_output(self, output):
        """Парсинг вывода ls -l для заполнения дерева."""
        lines = [l for l in output.splitlines() if l.strip() and not l.startswith("debugfs:")]
        for line in lines:
            parts = re.split(r"\s+", line, maxsplit=7)
            if len(parts) >= 8:
                inode = parts[0]
                perms = parts[1]
                links = parts[2]
                uid = parts[3]
                gid = parts[4]
                size = parts[5]
                date = parts[6]
                name = parts[7]
                ftype = "d" if perms.startswith("d") else ("l" if perms.startswith("l") else "f")
                self.tree.insert("", "end", text=name, values=(inode, ftype, size, perms, links, uid, gid, date))
            else:
                self.tree.insert("", "end", text=line, values=("", "", "", "", "", "", "", ""))
        self.status_bar.config(text="Дерево загружено")

    def on_tree_double_click(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        vals = self.tree.item(item, "values")
        inode = vals[0] if vals else None
        if inode:
            self.cmd_entry.set(f"stat {inode}")
            self.run_command()

    # --- Interactive forms ---
    def open_forms_menu(self):
        menu = tk.Toplevel(self.root)
        menu.title("Интерактивные формы команд")
        menu.geometry("500x400")
        ttk.Button(menu, text="stat (интерактивно)", command=lambda: (menu.destroy(), self.open_interactive("stat"))).pack(fill="x", padx=8, pady=6)
        ttk.Button(menu, text="ncheck (найти путь по inode)", command=lambda: (menu.destroy(), self.open_interactive("ncheck"))).pack(fill="x", padx=8, pady=6)
        ttk.Button(menu, text="icheck (блок->inode)", command=lambda: (menu.destroy(), self.open_interactive("icheck"))).pack(fill="x", padx=8, pady=6)
        ttk.Button(menu, text="dump (скачать inode в файл)", command=lambda: (menu.destroy(), self.open_interactive("dump"))).pack(fill="x", padx=8, pady=6)
        ttk.Button(menu, text="readblock", command=lambda: (menu.destroy(), self.open_interactive("readblock"))).pack(fill="x", padx=8, pady=6)
        ttk.Button(menu, text="write (записать локальный файл в FS)", command=lambda: (menu.destroy(), self.open_interactive("write"))).pack(fill="x", padx=8, pady=6)
        ttk.Button(menu, text="mkdir", command=lambda: (menu.destroy(), self.open_interactive("mkdir"))).pack(fill="x", padx=8, pady=6)
        ttk.Button(menu, text="rm (удаление)", command=lambda: (menu.destroy(), self.open_interactive("rm"))).pack(fill="x", padx=8, pady=6)
        ttk.Button(menu, text="set_inode (изменить права/uid/gid)", command=lambda: (menu.destroy(), self.open_interactive("set_inode"))).pack(fill="x", padx=8, pady=6)
        ttk.Button(menu, text="Закрыть", command=menu.destroy).pack(side="bottom", pady=10)

    def open_interactive(self, cmd_type):
        win = tk.Toplevel(self.root)
        win.transient(self.root)
        win.grab_set()
        win.title(f"Форма: {cmd_type}")
        frm = ttk.Frame(win, padding=10)
        frm.pack(fill="both", expand=True)

        def submit_and_close(command_text):
            win.destroy()
            self.cmd_entry.set(command_text)
            self.run_command()

        if cmd_type == "cd":
            ttk.Label(frm, text="Путь в FS (например /path):").pack(anchor="w")
            p_e = ttk.Entry(frm)
            p_e.pack(fill="x")
            ttk.Button(frm, text="Перейти", command=lambda: submit_and_close(f"cd {p_e.get().strip()}")).pack(pady=8)

        elif cmd_type == "stat":
            ttk.Label(frm, text="Inode:").pack(anchor="w")
            inode_e = ttk.Entry(frm)
            inode_e.pack(fill="x")
            ttk.Button(frm, text="Выполнить stat", command=lambda: submit_and_close(f"stat {inode_e.get().strip()}")).pack(pady=8)

        elif cmd_type == "ncheck":
            ttk.Label(frm, text="Inode:").pack(anchor="w")
            inode_e = ttk.Entry(frm)
            inode_e.pack(fill="x")
            ttk.Button(frm, text="Найти путь", command=lambda: submit_and_close(f"ncheck {inode_e.get().strip()}")).pack(pady=8)

        elif cmd_type == "icheck":
            ttk.Label(frm, text="Block number:").pack(anchor="w")
            blk_e = ttk.Entry(frm)
            blk_e.pack(fill="x")
            ttk.Button(frm, text="icheck", command=lambda: submit_and_close(f"icheck {blk_e.get().strip()}")).pack(pady=8)

        elif cmd_type == "dump":
            ttk.Label(frm, text="Inode:").pack(anchor="w")
            inode_e = ttk.Entry(frm)
            inode_e.pack(fill="x")
            ttk.Label(frm, text="Сохранить в файл (локально):").pack(anchor="w")
            out_e = ttk.Entry(frm)
            out_e.pack(fill="x")
            def do_dump():
                inode = inode_e.get().strip()
                outp = out_e.get().strip()
                if not inode or not outp:
                    messagebox.showwarning("Внимание", "Заполните inode и имя файла")
                    return
                submit_and_close(f"dump {inode} {outp}")
            ttk.Button(frm, text="Dump", command=do_dump).pack(pady=8)

        elif cmd_type == "readblock":
            ttk.Label(frm, text="Block number:").pack(anchor="w")
            blk_e = ttk.Entry(frm)
            blk_e.pack(fill="x")
            ttk.Label(frm, text="Сохранить в файл (локально):").pack(anchor="w")
            out_e = ttk.Entry(frm)
            out_e.pack(fill="x")
            ttk.Button(frm, text="Readblock", command=lambda: submit_and_close(f"readblock {blk_e.get().strip()} {out_e.get().strip()}")).pack(pady=8)

        elif cmd_type == "write":
            ttk.Label(frm, text="Локальный файл:").pack(anchor="w")
            local_e = ttk.Entry(frm)
            local_e.pack(fill="x")
            ttk.Button(frm, text="Обзор...", command=lambda: self._browse_and_set(local_e)).pack(pady=4)
            ttk.Label(frm, text="Путь в FS (куда записать):").pack(anchor="w")
            dest_e = ttk.Entry(frm)
            dest_e.pack(fill="x")
            def do_write():
                l = local_e.get().strip(); d = dest_e.get().strip()
                if not l or not d:
                    messagebox.showwarning("Внимание", "Укажите локальный файл и путь назначения")
                    return
                submit_and_close(f"write {l} {d}")
            ttk.Button(frm, text="Write", command=do_write).pack(pady=8)

        elif cmd_type == "mkdir":
            ttk.Label(frm, text="Каталог (внутри FS):").pack(anchor="w")
            path_e = ttk.Entry(frm)
            path_e.pack(fill="x")
            ttk.Button(frm, text="Создать", command=lambda: submit_and_close(f"mkdir {path_e.get().strip()}")).pack(pady=8)

        elif cmd_type == "rm":
            ttk.Label(frm, text="Путь (внутри FS) для удаления:").pack(anchor="w")
            path_e = ttk.Entry(frm)
            path_e.pack(fill="x")
            ttk.Button(frm, text="Удалить", command=lambda: submit_and_close(f"rm {path_e.get().strip()}")).pack(pady=8)

        elif cmd_type == "set_inode":
            ttk.Label(frm, text="Inode:").pack(anchor="w")
            inode_e = ttk.Entry(frm); inode_e.pack(fill="x")
            ttk.Label(frm, text="Поле для изменения (mode/uid/gid):").pack(anchor="w")
            field_e = ttk.Combobox(frm, values=["mode", "uid", "gid"], state="readonly"); field_e.pack(fill="x")
            ttk.Label(frm, text="Новое значение:").pack(anchor="w")
            val_e = ttk.Entry(frm); val_e.pack(fill="x")
            def do_set():
                inode = inode_e.get().strip(); field = field_e.get(); val = val_e.get().strip()
                if not inode or not field or not val:
                    messagebox.showwarning("Внимание", "Заполните все поля")
                    return
                submit_and_close(f"set_inode {inode} {field} {val}")
            ttk.Button(frm, text="Применить", command=do_set).pack(pady=8)

        else:
            ttk.Label(frm, text="Неизвестная форма").pack()
            ttk.Button(frm, text="Закрыть", command=win.destroy).pack(pady=6)

    def _browse_and_set(self, entry_widget):
        p = filedialog.askopenfilename()
        if p:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, p)

    def create_test_scenarios_tab(self):
        """Создание вкладки с тестовыми сценариями."""
        # Информационная секция
        info_frame = ttk.LabelFrame(self.test_frame, text="Информация", padding=10)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        info_text = (
            "Готовые тестовые сценарии для проверки файловой системы.\n"
            "Выберите сценарий и нажмите 'Запустить' для автоматического выполнения."
        )
        ttk.Label(info_frame, text=info_text, foreground="blue", wraplength=600).pack(anchor="w")

        # Секция сценариев
        scenarios_frame = ttk.LabelFrame(self.test_frame, text="Доступные сценарии", padding=10)
        scenarios_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Список сценариев
        scenarios_list_frame = ttk.Frame(scenarios_frame)
        scenarios_list_frame.pack(fill="both", expand=True)

        # Левая колонка - список сценариев
        left_frame = ttk.Frame(scenarios_list_frame)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        ttk.Label(left_frame, text="Сценарии:", font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 5))

        self.scenarios_listbox = tk.Listbox(left_frame, height=12, font=("Arial", 9))
        self.scenarios_listbox.pack(fill="both", expand=True)
        self.scenarios_listbox.bind("<<ListboxSelect>>", self.on_scenario_select)

        # Правая колонка - описание
        right_frame = ttk.Frame(scenarios_list_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))

        ttk.Label(right_frame, text="Описание:", font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 5))
        
        self.scenario_desc_text = tk.Text(right_frame, wrap="word", height=12, font=("Arial", 9), 
                                          bg="#f5f5f5", relief=tk.FLAT)
        self.scenario_desc_text.pack(fill="both", expand=True)

        # Кнопки управления
        buttons_frame = ttk.Frame(scenarios_frame)
        buttons_frame.pack(fill="x", pady=(10, 0))

        ttk.Button(buttons_frame, text="Запустить выбранный сценарий", 
                  command=self.run_selected_scenario).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Запустить все сценарии", 
                  command=self.run_all_scenarios).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Очистить вывод", 
                  command=self.clear_output).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Справка", 
                  command=self.show_help).pack(side="left", padx=5)

        # Заполняем список сценариев
        self.test_scenarios = self._get_test_scenarios()
        for scenario in self.test_scenarios:
            self.scenarios_listbox.insert(tk.END, scenario["name"])

    def _get_test_scenarios(self):
        """Возвращает список тестовых сценариев."""
        return [
            {
                "name": "1. Базовая информация о ФС",
                "description": (
                    "Получает базовую информацию о файловой системе:\n"
                    "• Тип файловой системы\n"
                    "• Размер в блоках\n"
                    "• Общая статистика\n\n"
                    "Команда: stats"
                ),
                "commands": ["stats"]
            },
            {
                "name": "2. Список корневой директории",
                "description": (
                    "Выводит список всех файлов и директорий в корне:\n"
                    "• Inode номер\n"
                    "• Права доступа\n"
                    "• Размер\n"
                    "• Владелец\n\n"
                    "Команда: ls -l /"
                ),
                "commands": ["ls -l /"]
            },
            {
                "name": "3. Текущая рабочая директория",
                "description": (
                    "Определяет текущую рабочую директорию в файловой системе.\n\n"
                    "Команда: pwd"
                ),
                "commands": ["pwd"]
            },
            {
                "name": "4. Информация о inode 2 (корневой каталог)",
                "description": (
                    "Получает детальную информацию о inode 2 (обычно корневой каталог):\n"
                    "• Тип файла\n"
                    "• Размер\n"
                    "• Права доступа\n"
                    "• Владелец и группа\n"
                    "• Временные метки\n\n"
                    "Команда: stat 2"
                ),
                "commands": ["stat 2"]
            },
            {
                "name": "5. Поиск пути по inode",
                "description": (
                    "Находит путь к файлу по его inode номеру.\n"
                    "Использует inode 2 (корневой каталог) для примера.\n\n"
                    "Команда: ncheck 2"
                ),
                "commands": ["ncheck 2"]
            },
            {
                "name": "6. Проверка блока данных",
                "description": (
                    "Определяет, какой inode использует указанный блок.\n"
                    "Использует блок 0 для примера.\n\n"
                    "Команда: icheck 0"
                ),
                "commands": ["icheck 0"]
            },
            {
                "name": "7. Полная диагностика ФС",
                "description": (
                    "Выполняет комплексную проверку файловой системы:\n"
                    "• Статистика ФС\n"
                    "• Список корневых файлов\n"
                    "• Информация о корневом каталоге\n\n"
                    "Команды: stats, ls -l /, stat 2"
                ),
                "commands": ["stats", "ls -l /", "stat 2"]
            },
            {
                "name": "8. Проверка структуры каталогов",
                "description": (
                    "Анализирует структуру основных системных каталогов:\n"
                    "• Корневой каталог\n"
                    "• Попытка просмотра /etc, /home, /var\n\n"
                    "Команды: ls -l /, ls -l /etc, ls -l /home, ls -l /var"
                ),
                "commands": ["ls -l /", "ls -l /etc", "ls -l /home", "ls -l /var"]
            }
        ]

    def on_scenario_select(self, event):
        """Обновление описания при выборе сценария."""
        selection = self.scenarios_listbox.curselection()
        if selection:
            idx = selection[0]
            scenario = self.test_scenarios[idx]
            self.scenario_desc_text.delete(1.0, tk.END)
            self.scenario_desc_text.insert(1.0, scenario["description"])

    def run_selected_scenario(self):
        """Запуск выбранного тестового сценария."""
        if not self._validate_device():
            return
        
        selection = self.scenarios_listbox.curselection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите сценарий из списка!")
            return

        idx = selection[0]
        scenario = self.test_scenarios[idx]
        
        self.status_bar.config(text=f"Выполнение сценария: {scenario['name']}...")
        self.log(f"TEST SCENARIO START: {scenario['name']}")
        
        # Очищаем вывод
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"=== Тестовый сценарий: {scenario['name']} ===\n")
        self.output_text.insert(tk.END, f"Описание: {scenario['description'].split(chr(10))[0]}\n")
        self.output_text.insert(tk.END, "=" * 60 + "\n\n")

        # Выполняем команды последовательно
        self._execute_scenario_commands(scenario["commands"], 0)

    def _execute_scenario_commands(self, commands, index):
        """Рекурсивное выполнение команд сценария."""
        if index >= len(commands):
            self.status_bar.config(text="Сценарий завершён")
            self.log("TEST SCENARIO COMPLETE")
            return

        command = commands[index]
        self.output_text.insert(tk.END, f"\n[Команда {index + 1}/{len(commands)}]: {command}\n")
        self.output_text.insert(tk.END, "-" * 60 + "\n")
        self.root.update_idletasks()

        args = self._build_cmd_args()
        input_data = f"{command}\nquit\n"
        
        def run_next():
            self._execute_scenario_commands(commands, index + 1)

        def on_complete(proc):
            self.output_text.insert(tk.END, proc.stdout.replace("debugfs:", ""))
            if proc.stderr:
                self.output_text.insert(tk.END, f"\n[STDERR]:\n{proc.stderr}")
            self.output_text.insert(tk.END, "\n")
            self.root.update_idletasks()
            # Небольшая задержка перед следующей командой
            self.root.after(500, run_next)

        thread = threading.Thread(target=self._run_scenario_command, 
                                 args=(args, input_data, command, on_complete))
        thread.daemon = True
        thread.start()

    def _run_scenario_command(self, args, input_data, command, callback):
        """Выполнение команды сценария в отдельном потоке."""
        try:
            proc = subprocess.run(args, input=input_data, capture_output=True, text=True, timeout=30)
            self.root.after(0, callback, proc)
        except subprocess.TimeoutExpired:
            self.root.after(0, lambda: (
                self.output_text.insert(tk.END, f"\n[ОШИБКА] Таймаут выполнения команды: {command}\n"),
                self.status_bar.config(text="Таймаут")
            ))
        except Exception as e:
            self.root.after(0, lambda: (
                self.output_text.insert(tk.END, f"\n[ОШИБКА] {e}\n"),
                self.status_bar.config(text="Ошибка")
            ))

    def run_all_scenarios(self):
        """Запуск всех тестовых сценариев последовательно."""
        if not self._validate_device():
            return
        
        response = messagebox.askyesno(
            "Подтверждение",
            f"Выполнить все {len(self.test_scenarios)} сценариев?\n"
            "Это может занять некоторое время."
        )
        if not response:
            return

        self.status_bar.config(text="Выполнение всех сценариев...")
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "=== ЗАПУСК ВСЕХ ТЕСТОВЫХ СЦЕНАРИЕВ ===\n")
        self.output_text.insert(tk.END, "=" * 60 + "\n\n")
        self.log("ALL TEST SCENARIOS START")

        # Запускаем первый сценарий
        self._run_all_scenarios_recursive(0)

    def _run_all_scenarios_recursive(self, scenario_idx):
        """Рекурсивный запуск всех сценариев."""
        if scenario_idx >= len(self.test_scenarios):
            self.status_bar.config(text="Все сценарии завершены")
            self.output_text.insert(tk.END, "\n" + "=" * 60 + "\n")
            self.output_text.insert(tk.END, "=== ВСЕ СЦЕНАРИИ ЗАВЕРШЕНЫ ===\n")
            self.log("ALL TEST SCENARIOS COMPLETE")
            return

        scenario = self.test_scenarios[scenario_idx]
        self.output_text.insert(tk.END, f"\n\n{'=' * 60}\n")
        self.output_text.insert(tk.END, f"СЦЕНАРИЙ {scenario_idx + 1}: {scenario['name']}\n")
        self.output_text.insert(tk.END, f"{'=' * 60}\n\n")
        self.root.update_idletasks()

        # Выполняем команды сценария
        self._execute_all_scenarios_commands(scenario["commands"], 0, scenario_idx)

    def _execute_all_scenarios_commands(self, commands, cmd_idx, scenario_idx):
        """Выполнение команд сценария в контексте всех сценариев."""
        if cmd_idx >= len(commands):
            # Переходим к следующему сценарию
            self.root.after(1000, lambda: self._run_all_scenarios_recursive(scenario_idx + 1))
            return

        command = commands[cmd_idx]
        self.output_text.insert(tk.END, f"[{scenario_idx + 1}.{cmd_idx + 1}] {command}\n")
        self.output_text.insert(tk.END, "-" * 60 + "\n")
        self.root.update_idletasks()

        args = self._build_cmd_args()
        input_data = f"{command}\nquit\n"

        def on_complete(proc):
            self.output_text.insert(tk.END, proc.stdout.replace("debugfs:", ""))
            if proc.stderr:
                self.output_text.insert(tk.END, f"\n[STDERR]:\n{proc.stderr}")
            self.output_text.insert(tk.END, "\n")
            self.root.update_idletasks()
            self.root.after(500, lambda: self._execute_all_scenarios_commands(commands, cmd_idx + 1, scenario_idx))

        thread = threading.Thread(target=self._run_scenario_command, 
                                 args=(args, input_data, command, on_complete))
        thread.daemon = True
        thread.start()

    def clear_output(self):
        """Очистка области вывода."""
        self.output_text.delete(1.0, tk.END)

    def show_help(self):
        """Отображение справки по использованию программы."""
        help_window = tk.Toplevel(self.root)
        help_window.title("Справка по использованию DebugFS GUI")
        help_window.geometry("700x600")
        help_window.transient(self.root)

        # Создаем текстовую область с прокруткой
        frame = ttk.Frame(help_window, padding=10)
        frame.pack(fill="both", expand=True)

        text_widget = tk.Text(frame, wrap="word", font=("Arial", 10), padx=10, pady=10)
        scrollbar = ttk.Scrollbar(frame, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        help_text = """
═══════════════════════════════════════════════════════════════
           КРАТКАЯ СПРАВКА ПО ИСПОЛЬЗОВАНИЮ
═══════════════════════════════════════════════════════════════

1. НАЧАЛО РАБОТЫ
────────────────
• Укажите устройство или образ диска в поле "Устройство/Образ"
• Нажмите "Получить инфо FS" для проверки подключения
• Включите "Использовать sudo" если требуется

2. ОСНОВНЫЕ ВКЛАДКИ
───────────────────
• "Команды" - выполнение команд debugfs вручную
• "Файловая система" - визуальное дерево файлов
• "Тестовые сценарии" - готовые наборы команд

3. ВЫПОЛНЕНИЕ КОМАНД
────────────────────
• Введите команду в поле "Ввод команды"
• Нажмите "Выполнить" или Enter
• Используйте "Формы..." для интерактивного ввода

Основные команды:
  ls -l [путь]     - список файлов
  stat <inode>     - информация о inode
  pwd              - текущая директория
  cd <путь>        - смена директории
  stats            - статистика ФС
  ncheck <inode>   - найти путь по inode
  icheck <block>   - найти inode по блоку

4. ТЕСТОВЫЕ СЦЕНАРИИ
────────────────────
• Выберите сценарий из списка
• Нажмите "Запустить выбранный сценарий"
• Или "Запустить все сценарии" для полной проверки
• Результаты отображаются на вкладке "Команды"

5. БЕЗОПАСНОСТЬ
──────────────
⚠ Safe Mode включен по умолчанию - блокирует опасные операции
⚠ Опасные команды требуют подтверждения (ввод CONFIRM)
⚠ Всегда работайте с копиями образов дисков!

6. РЕШЕНИЕ ПРОБЛЕМ
──────────────────
• "debugfs не найдена" → установите e2fsprogs
• "Permission denied" → включите sudo или запустите от root
• "Устройство занято" → размонтируйте устройство (umount)

7. ЛОГИРОВАНИЕ
──────────────
Все операции записываются в файл: debugfs_gui.log

═══════════════════════════════════════════════════════════════

Подробная инструкция сохранена в файле: ИНСТРУКЦИЯ.txt

═══════════════════════════════════════════════════════════════
        """
        
        text_widget.insert(1.0, help_text)
        text_widget.config(state=tk.DISABLED)  # Только для чтения

        scrollbar.pack(side="right", fill="y")
        text_widget.pack(side="left", fill="both", expand=True)

        ttk.Button(help_window, text="Закрыть", command=help_window.destroy).pack(pady=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = DebugFSGui(root)
    root.mainloop()
