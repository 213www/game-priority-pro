# -*- coding: utf-8 -*-
"""
游戏优先级优化工具 Pro  v2.0
=================================================================
v2.0 主要改动
1. 全新深色 GUI 界面（不再是控制台窗口），常驻后台运行
2. 修复 v1.0「部分游戏进程识别不到、优先级提不上去」的问题：
   - 匹配方式由「名称完全相等」改为「名称 + 关键字 + 安装路径 + 窗口标题」四重识别
   - 补齐各游戏启动器 / 主程序（-Win64-Shipping）等真实进程名
   - 自动启用 SeDebugPrivilege 调试权限（v1.0 缺这一步，导致受保护进程取不到句柄）
   - 每次写入后回读校验，被反作弊重置会持续重新应用
   - 权限不足 / 受自我保护 / 不存在，都在界面上明确提示，不再静默 pass
3. 支持自定义进程名（游戏 / 反作弊），解决新版本改了 exe 名的情况
4. 实时进程列表、彩色运行日志、累计统计、运行时长
=================================================================
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import ctypes
from ctypes import wintypes

import psutil

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox

APP_TITLE = "游戏优先级优化工具 Pro"
APP_VERSION = "2.0"


# =================================================================
# 一、Win32 底层封装（优先级读写 / 提权 / 窗口枚举）
# =================================================================

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

IDLE_PRIORITY_CLASS = 0x00000040
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS = 0x00000020
ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
HIGH_PRIORITY_CLASS = 0x00000080
REALTIME_PRIORITY_CLASS = 0x00000100

PRIORITY_LABEL = {
    IDLE_PRIORITY_CLASS: "最低",
    BELOW_NORMAL_PRIORITY_CLASS: "低于正常",
    NORMAL_PRIORITY_CLASS: "正常",
    ABOVE_NORMAL_PRIORITY_CLASS: "高于正常",
    HIGH_PRIORITY_CLASS: "高",
    REALTIME_PRIORITY_CLASS: "实时",
}

# 函数原型（必须显式声明，否则 64 位系统下句柄会被截断成 32 位 → 句柄无效/改不动）
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.SetPriorityClass.restype = wintypes.BOOL
kernel32.GetPriorityClass.argtypes = [wintypes.HANDLE]
kernel32.GetPriorityClass.restype = wintypes.DWORD
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE

user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.GetParent.argtypes = [wintypes.HWND]
user32.GetParent.restype = wintypes.HWND
user32.EnumWindows.argtypes = [ctypes.c_void_p, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(silent: bool = False) -> bool:
    """以管理员身份重启本程序；返回是否成功唤起（用户取消 UAC 时为 False）"""
    try:
        if getattr(sys, "frozen", False):
            exe, params = sys.executable, " ".join(sys.argv[1:])
        else:
            exe = sys.executable
            params = " ".join(f'"{a}"' if " " in a else a
                              for a in [os.path.abspath(__file__)] + sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(ret) > 32
    except Exception as exc:  # pragma: no cover
        if not silent:
            messagebox.showerror(APP_TITLE, f"申请管理员权限失败：{exc}")
        return False


def enable_debug_privilege() -> bool:
    """启用 SeDebugPrivilege，v1.0 缺失此步骤，是取不到受保护进程句柄的主因之一"""
    SE_DEBUG_NAME = "SeDebugPrivilege"
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x0002

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPWSTR, wintypes.LPWSTR,
                                               ctypes.POINTER(LUID)]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL,
                                               ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.c_void_p, ctypes.c_void_p]
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     ctypes.byref(token)):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ok = advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp),
                                           ctypes.sizeof(tp), None, None)
        return bool(ok) and ctypes.get_last_error() == 0
    finally:
        kernel32.CloseHandle(token)


def get_priority_class(pid: int) -> int | None:
    """读取进程优先级，读不到返回 None（受保护/已退出）"""
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        value = kernel32.GetPriorityClass(handle)
        return int(value) if value else None
    finally:
        kernel32.CloseHandle(handle)


def set_priority_class(pid: int, value: int) -> tuple[bool, int]:
    """设置进程优先级，返回 (是否成功, 错误码)"""
    handle = kernel32.OpenProcess(
        PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False, ctypes.get_last_error()
    try:
        ok = kernel32.SetPriorityClass(handle, value)
        return bool(ok), (0 if ok else ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(handle)


def error_text(code: int) -> str:
    return {
        5: "权限不足",
        6: "句柄无效",
        87: "系统不支持",
        0: "未知",
    }.get(code, f"失败({code})")


def visible_window_titles() -> dict[int, str]:
    """枚举可见窗口标题 → {pid: title}，用于游戏进程兜底识别"""
    result: dict[int, str] = {}
    proto = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _callback(hwnd, _lparam):
        try:
            if not user32.IsWindowVisible(hwnd):
                return True
            length = user32.GetWindowTextLengthW(hwnd)
            if length < 3:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value.strip()
            if title:
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                result.setdefault(pid.value, title)
        except Exception:
            pass
        return True

    try:
        user32.EnumWindows(proto(_callback), 0)
    except Exception:
        pass
    return result


# =================================================================
# 二、进程识别规则（名称 / 关键字 / 窗口标题）
# =================================================================

GAME_RULES = [
    {
        "group": "穿越火线",
        "names": ["crossfire.exe", "crossfire_x64.exe", "crossfirehd.exe",
                  "cfhd.exe", "cf.exe", "crossfirelauncher.exe"],
        "kw": ["crossfire"],
        "titles": ["穿越火线", "crossfire"],
    },
    {
        "group": "无畏契约",
        "names": ["valorant.exe", "valorant-win64-shipping.exe",
                  "valorantgame.exe", "valorant-win64-test.exe"],
        "kw": ["valorant"],
        "titles": ["valorant", "无畏契约"],
    },
    {
        "group": "三角洲行动",
        "names": ["deltaforceclient-win64-shipping.exe", "deltaforceclient.exe",
                  "deltaforce.exe", "deltagame.exe", "deltaforce-win64-shipping.exe"],
        "kw": ["deltaforce", "deltagame"],
        "titles": ["三角洲", "delta force"],
    },
    {
        "group": "暗区突围",
        "names": ["arenabreakoutinfinite.exe", "arenabreakoutinfinite-win64-shipping.exe",
                  "abinfinite-win64-shipping.exe", "abinfinite.exe",
                  "arena-breakout-infinite.exe"],
        "kw": ["arenabreakout", "abinfinite"],
        "titles": ["暗区突围", "arena breakout"],
    },
    {
        "group": "PUBG / 和平精英",
        "names": ["tslgame.exe", "pubg.exe", "gameloop.exe", "gameloop.7z.exe"],
        "kw": ["tslgame"],
        "titles": ["绝地求生", "和平精英", "pubg"],
    },
]

ACE_RULES = [
    {
        "group": "ACE 反作弊",
        "names": ["ace-tray.exe", "ace-guard.exe", "ace-guard client.exe",
                  "ace-guard service.exe", "sguard64.exe", "sguard.exe",
                  "aceservice.exe", "anticheatexpertservice.exe", "ace-base.exe",
                  "ace-game.exe"],
        "kw": ["ace-tray", "ace-guard", "sguard", "anticheatexpert"],
        "titles": [],
    },
    {
        "group": "Vanguard 反作弊",
        "names": ["vgc.exe", "vgksvc.exe", "vgk.exe"],
        "kw": ["vgc.exe", "vanguard"],
        "titles": [],
    },
    {
        "group": "TenProtect 反作弊",
        "names": ["tmmon.exe", "tphelper.exe", "tenprotect.exe", "tasservice.exe"],
        "kw": ["tmmon", "tphelper", "tenprotect"],
        "titles": [],
    },
]

# 窗口标题兜底识别时要排除的进程（浏览器/编辑器等，标题里可能带游戏名）
TITLE_IGNORE = {
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
    "brave.exe", "explorer.exe", "code.exe", "notepad.exe", "python.exe",
    "pythonw.exe", "javaw.exe", "java.exe", "doubao.exe", "wechat.exe",
    "qq.exe", "discord.exe", "steam.exe", "steamwebhelper.exe", "wemeetapp.exe",
    "powershell.exe", "windowsterminal.exe", "cmd.exe", "searchhost.exe",
    "applicationframehost.exe", "taskmgr.exe", "bilibili.exe", "wrapper.exe",
}


_EXE_CACHE: dict[int, str] = {}


def _safe_exe_path(pid: int) -> str:
    """读取进程 exe 路径（按 pid 缓存，避免每轮扫描都重复取）"""
    if pid in _EXE_CACHE:
        return _EXE_CACHE[pid]
    try:
        path = psutil.Process(pid).exe() or ""
    except Exception:
        path = ""
    if len(_EXE_CACHE) > 600:
        _EXE_CACHE.clear()
    _EXE_CACHE[pid] = path
    return path


def _match(name: str, path: str, rules: list[dict]) -> str | None:
    low_name = name.lower()
    low_path = path.lower()
    for rule in rules:
        if low_name in rule["names"]:
            return rule["group"]
    for rule in rules:
        for kw in rule["kw"]:
            if kw in low_name or (low_path and kw in low_path):
                return rule["group"]
    return None


def detect_processes(custom_games: list[str], custom_ace: list[str]) -> dict[int, dict]:
    """返回 {pid: {kind, group, name}}"""
    game_rules = list(GAME_RULES)
    ace_rules = list(ACE_RULES)
    if custom_games:
        game_rules.insert(0, {"group": "自定义游戏",
                              "names": [n.strip().lower() for n in custom_games if n.strip()],
                              "kw": [n.strip().lower().replace(".exe", "")
                                     for n in custom_games if n.strip()],
                              "titles": []})
    if custom_ace:
        ace_rules.insert(0, {"group": "自定义反作弊",
                             "names": [n.strip().lower() for n in custom_ace if n.strip()],
                             "kw": [n.strip().lower().replace(".exe", "")
                                    for n in custom_ace if n.strip()],
                             "titles": []})

    procs: list[tuple[int, str]] = []
    for proc in psutil.process_iter(["pid", "name"]):
        pid = proc.info.get("pid")
        name = proc.info.get("name") or ""
        if pid and name:
            procs.append((pid, name))

    names_by_pid = {pid: name for pid, name in procs}
    hits: dict[int, dict] = {}

    for pid, name in procs:
        path = ""
        group = _match(name, path, game_rules)
        kind = "game"
        if group is None:
            group = _match(name, path, ace_rules)
            kind = "ace"
        if group is None:
            # 名称没命中时再看安装路径（游戏的 exe 名有时是 Shipping.exe 之类）
            path = _safe_exe_path(pid)
            if path:
                group = _match(name, path, game_rules)
                kind = "game"
                if group is None:
                    group = _match(name, path, ace_rules)
                    kind = "ace"
        if group:
            hits[pid] = {"kind": kind, "group": group, "name": name}

    # 兜底：按游戏窗口标题反查 PID（解决改名/未收录的进程识别不到）
    for pid, title in visible_window_titles().items():
        if pid in hits:
            continue
        name = names_by_pid.get(pid)
        if not name or name.lower() in TITLE_IGNORE:
            continue
        title_low = title.lower()
        for rule in game_rules:
            if any(t.lower() in title_low for t in rule.get("titles", [])):
                hits[pid] = {"kind": "game", "group": rule["group"], "name": name}
                break
    return hits


def perform_scan(cfg: dict, custom_games: list[str], custom_ace: list[str],
                 apply: bool = True, restore: bool = False) -> dict:
    """扫描并（可选）调整优先级，返回界面需要的结构化结果"""
    hits = detect_processes(custom_games, custom_ace)
    game_target = NORMAL_PRIORITY_CLASS if restore else cfg["game_target"]
    ace_target = NORMAL_PRIORITY_CLASS if restore else cfg["ace_target"]

    game_rows, ace_rows, logs = [], [], []
    changed = 0

    for pid, info in hits.items():
        kind = info["kind"]
        name = info["name"]
        target = game_target if kind == "game" else ace_target
        current = get_priority_class(pid)
        current_label = PRIORITY_LABEL.get(current, "状态受限" if current is None else "未知")

        row = {
            "pid": pid, "name": name, "group": info["group"],
            "cur": current_label, "prev": current_label,
            "target": PRIORITY_LABEL.get(target, "正常"),
            "status": "", "tag": "norm",
        }

        if current is None:
            row.update(status="状态受限", tag="warn")
        elif not apply:
            if current == target:
                row.update(status="已达标", tag="ok")
            else:
                row.update(status="待优化", tag="norm")
        elif current == target:
            row.update(status="已优化", tag="ok")
        else:
            ok, err = set_priority_class(pid, target)
            if not ok:
                row.update(status=error_text(err), tag="warn" if err == 5 else "err")
            else:
                readback = get_priority_class(pid)
                if readback == target:
                    changed += 1
                    if restore:
                        row.update(status="已恢复", tag="ok")
                    elif kind == "game":
                        row.update(status="已提升", tag="ok")
                    else:
                        row.update(status="已降低", tag="ok")
                    row["cur"] = PRIORITY_LABEL.get(target, row["target"])
                else:
                    row.update(status="被重置", tag="warn")

        (game_rows if kind == "game" else ace_rows).append(row)

    return {
        "games": sorted(game_rows, key=lambda r: r["name"].lower()),
        "ace": sorted(ace_rows, key=lambda r: r["name"].lower()),
        "changed": changed,
        "logs": logs,
    }


# =================================================================
# 三、配置
# =================================================================

DEFAULT_CONFIG = {
    "game_target": HIGH_PRIORITY_CLASS,
    "ace_target": IDLE_PRIORITY_CLASS,
    "interval": 3,
    "auto_start": True,
    "auto_elevate": True,
    "custom_games": [],
    "custom_ace": [],
}


def app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


CONFIG_PATH = os.path.join(app_dir(), "config_pro.json")


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key in cfg:
            if key in data:
                cfg[key] = data[key]
    except Exception:
        pass
    return cfg


def save_config(cfg: dict) -> None:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# =================================================================
# 四、配色 / 基础控件
# =================================================================

BG = "#0B0E13"
PANEL = "#141A22"
PANEL_2 = "#1B232D"
PANEL_3 = "#222C38"
BORDER = "#26313D"
TEXT = "#E8EFF7"
MUTED = "#8792A2"
ACCENT = "#FF4655"
ACCENT_DARK = "#D83745"
CYAN = "#26D0E0"
GREEN = "#3DDC97"
AMBER = "#FFB020"
RED = "#FF6B6B"

FONT = "Microsoft YaHei UI"
MONO = "Consolas"


def round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw):
    r = max(1, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
           x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


class RoundButton(tk.Canvas):
    """自绘圆角按钮，带 hover / press 态"""

    def __init__(self, master, text="", command=None, width=120, height=34,
                 fill=ACCENT, hover=ACCENT_DARK, fg="#FFFFFF",
                 font=(FONT, 9, "bold"), bg=BG, radius=8):
        super().__init__(master, width=width, height=height, bg=bg,
                         highlightthickness=0, bd=0, cursor="hand2")
        self._text = text
        self._cmd = command
        self._cw, self._ch = width, height
        self._fill, self._hover, self._fg = fill, hover, fg
        self._font = font
        self._radius = radius
        self._enabled = True
        self._pressed = False
        self._shape = None
        self._label = None
        self._draw(fill)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _draw(self, color):
        self.delete("all")
        self._shape = round_rect(self, 1, 1, self._cw - 1, self._ch - 1,
                                 self._radius, fill=color, outline="")
        self._label = self.create_text(self._cw / 2, self._ch / 2, text=self._text,
                                       fill=self._fg, font=self._font)

    def _on_enter(self, _e=None):
        if self._enabled:
            self._draw(self._hover)

    def _on_leave(self, _e=None):
        if self._enabled:
            self._pressed = False
            self._draw(self._fill)

    def _on_press(self, _e=None):
        if self._enabled:
            self._pressed = True
            self._draw(self._hover)

    def _on_release(self, _e=None):
        if self._enabled and self._pressed:
            self._pressed = False
            self._draw(self._hover)
            if self._cmd:
                self._cmd()

    def set_text(self, text, fill=None, hover=None, fg=None):
        self._text = text
        if fill:
            self._fill = fill
        if hover:
            self._hover = hover
        if fg:
            self._fg = fg
        self._draw(self._fill)

    def set_enabled(self, enabled: bool):
        self._enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw(self._fill if enabled else PANEL_3)


class Pill(tk.Canvas):
    """圆角小胶囊标签"""

    def __init__(self, master, text="", fg=MUTED, fill=PANEL_2, dot=None,
                 font=(FONT, 9), bg=BG, height=26, padx=12, radius=None):
        super().__init__(master, width=80, height=height, bg=bg,
                         highlightthickness=0, bd=0)
        self._text, self._fg, self._fill, self._dot = text, fg, fill, dot
        self._font = tkfont.Font(family=font[0], size=font[1])
        self._h, self._padx = height, padx
        self._radius = radius if radius is not None else height / 2
        self._redraw()

    def _redraw(self):
        self.delete("all")
        text_w = self._font.measure(self._text)
        width = int(text_w + self._padx * 2 + (14 if self._dot else 0))
        self.configure(width=width)
        round_rect(self, 1, 1, width - 1, self._h - 1, self._radius,
                   fill=self._fill, outline="")
        x = self._padx
        if self._dot:
            cy = self._h / 2
            self.create_oval(x, cy - 3, x + 6, cy + 3, fill=self._dot, outline="")
            x += 14
        self.create_text(x, self._h / 2, text=self._text, anchor="w",
                         fill=self._fg, font=self._font)

    def update_state(self, text=None, fg=None, fill=None, dot=None):
        if text is not None:
            self._text = text
        if fg is not None:
            self._fg = fg
        if fill is not None:
            self._fill = fill
        if dot is not None:
            self._dot = dot
        self._redraw()


class GradientBar(tk.Canvas):
    """顶部渐变装饰条"""

    def __init__(self, master, height=2, bg=BG):
        super().__init__(master, height=height, bg=bg, highlightthickness=0, bd=0)
        self._h = height
        self.bind("<Configure>", self._redraw)

    def _redraw(self, _e=None):
        self.delete("all")
        w = self.winfo_width()
        if w <= 1:
            return
        c1 = (255, 70, 85)
        c2 = (38, 208, 224)
        c3 = (20, 26, 34)
        for i in range(w):
            t = i / max(1, w - 1)
            if t < 0.5:
                k = t / 0.5
                rgb = tuple(int(c1[j] + (c2[j] - c1[j]) * k) for j in range(3))
            else:
                k = (t - 0.5) / 0.5
                rgb = tuple(int(c2[j] + (c3[j] - c2[j]) * k) for j in range(3))
            self.create_line(i, 0, i, self._h, fill="#%02X%02X%02X" % rgb)


class ListPanel(tk.Frame):
    """左侧/右侧进程列表面板"""

    def __init__(self, master, title, subtitle, accent, on_add=None):
        super().__init__(master, bg=PANEL, highlightthickness=1,
                         highlightbackground=BORDER)
        head = tk.Frame(self, bg=PANEL)
        head.pack(fill="x", padx=14, pady=(12, 8))

        dot = tk.Canvas(head, width=10, height=10, bg=PANEL, highlightthickness=0)
        dot.create_oval(1, 1, 9, 9, fill=accent, outline="")
        dot.pack(side="left", pady=(2, 0))

        box = tk.Frame(head, bg=PANEL)
        box.pack(side="left", padx=(8, 0))
        tk.Label(box, text=title, bg=PANEL, fg=TEXT,
                 font=(FONT, 10, "bold")).pack(anchor="w")
        tk.Label(box, text=subtitle, bg=PANEL, fg=MUTED,
                 font=(FONT, 8)).pack(anchor="w")

        self.count = tk.Label(head, text="0 个", bg=PANEL, fg=MUTED, font=(FONT, 9))
        self.count.pack(side="right", pady=(6, 0))
        if on_add:
            RoundButton(head, "+ 自定义", command=on_add, width=68, height=24,
                        fill=PANEL_2, hover=PANEL_3, fg=MUTED,
                        font=(FONT, 8), bg=PANEL, radius=6).pack(side="right", padx=(0, 8))

        body = tk.Frame(self, bg=PANEL)
        body.pack(fill="both", expand=True, padx=(6, 6), pady=(0, 8))

        cols = ("name", "pid", "cur", "status")
        self.tree = ttk.Treeview(body, columns=cols, show="headings",
                                 style="Dark.Treeview", selectmode="browse")
        self.tree.heading("name", text="进程", anchor="w")
        self.tree.heading("pid", text="PID", anchor="center")
        self.tree.heading("cur", text="当前优先级", anchor="center")
        self.tree.heading("status", text="状态", anchor="center")
        self.tree.column("name", width=200, minwidth=110, anchor="w")
        self.tree.column("pid", width=54, minwidth=46, anchor="center", stretch=False)
        self.tree.column("cur", width=84, minwidth=68, anchor="center", stretch=False)
        self.tree.column("status", width=84, minwidth=68, anchor="center", stretch=False)

        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<MouseWheel>", self._on_wheel)

        self.tree.tag_configure("ok", foreground=GREEN)
        self.tree.tag_configure("warn", foreground=AMBER)
        self.tree.tag_configure("err", foreground=RED)
        self.tree.tag_configure("norm", foreground="#C2CCD8")
        self.tree.tag_configure("muted", foreground="#55606E")

    def _on_wheel(self, event):
        self.tree.yview_scroll(int(-event.delta / 120), "units")
        return "break"

    def update_rows(self, rows: list[dict], empty_text: str):
        tree = self.tree
        if not rows:
            for iid in tree.get_children():
                tree.delete(iid)
            tree.insert("", "end", iid="__empty__",
                        values=(empty_text, "", "", ""), tags=("muted",))
            self.count.configure(text="0 个")
            return

        if tree.exists("__empty__"):
            tree.delete("__empty__")
        wanted = set()
        for row in rows:
            iid = str(row["pid"])
            wanted.add(iid)
            values = (row["name"], row["pid"], row["cur"], row["status"])
            if tree.exists(iid):
                if tuple(tree.item(iid, "values")) != tuple(str(v) for v in values):
                    tree.item(iid, values=values, tags=(row["tag"],))
            else:
                tree.insert("", "end", iid=iid, values=values, tags=(row["tag"],))
        for iid in set(tree.get_children()) - wanted:
            if iid != "__empty__":
                tree.delete(iid)
        self.count.configure(text=f"{len(rows)} 个")


# =================================================================
# 五、主应用
# =================================================================

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.cfg = load_config()
        if not os.path.exists(CONFIG_PATH):
            save_config(self.cfg)  # 首次运行落盘，方便直接改配置文件
        self.queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.running = False
        self.scan_count = 0
        self.adjust_count = 0
        self.start_time: float | None = None
        self.last_status: dict[int, str] = {}
        self._tick_job = None

        self.no_admin = not is_admin()
        self.privilege_ok = enable_debug_privilege()

        self._build_style()
        self._build_ui()
        self._set_titlebar_dark()

        self.log_line("info", f"{APP_TITLE} v{APP_VERSION} 已启动"
                              f"（管理员：{'是' if not self.no_admin else '否'}，"
                              f"调试权限：{'已启用' if self.privilege_ok else '未启用'}）")
        self.log_line("info", "识别策略：进程名 + 关键字 + 安装路径 + 游戏窗口标题")

        self.root.after(150, self._poll_queue)
        self.root.after(200, self._on_first_show)

        if self.no_admin:
            self.root.after(900, self._warn_no_admin)

    # ---------------- 样式 ----------------

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Dark.Treeview",
                        background=PANEL, fieldbackground=PANEL,
                        foreground="#C2CCD8", borderwidth=0, relief="flat",
                        bordercolor=PANEL, lightcolor=PANEL, darkcolor=PANEL,
                        focuscolor=PANEL, rowheight=28, font=(FONT, 9))
        style.configure("Dark.Treeview.Heading",
                        background=PANEL, foreground=MUTED,
                        relief="flat", borderwidth=0,
                        font=(FONT, 9, "bold"), padding=(2, 6))
        style.map("Dark.Treeview",
                  background=[("selected", "#263445")],
                  foreground=[("selected", "#FFFFFF")])
        style.map("Dark.Treeview.Heading",
                  background=[("active", PANEL)])

        for orientation in ("Vertical", "Horizontal"):
            name = f"{orientation}.TScrollbar"
            style.configure(name, gripcount=0, relief="flat",
                            background=PANEL_2, troughcolor=PANEL, borderwidth=0,
                            arrowsize=12, arrowcolor=MUTED)
            style.map(name,
                      background=[("active", PANEL_3), ("!active", PANEL_2)],
                      arrowcolor=[("active", ACCENT)])

        style.configure("Dark.TCombobox",
                        fieldbackground=PANEL_2, background=PANEL_2,
                        foreground=TEXT, arrowcolor=TEXT, bordercolor=BORDER,
                        lightcolor=PANEL_2, darkcolor=PANEL_2,
                        insertcolor=TEXT, padding=(8, 4))
        style.map("Dark.TCombobox",
                  fieldbackground=[("readonly", PANEL_2), ("focus", PANEL_2)],
                  foreground=[("readonly", TEXT)],
                  bordercolor=[("focus", ACCENT)],
                  arrowcolor=[("active", ACCENT)])
        style.configure("Dark.TSpinbox",
                        fieldbackground=PANEL_2, background=PANEL_2,
                        foreground=TEXT, arrowcolor=TEXT, bordercolor=BORDER,
                        lightcolor=PANEL_2, darkcolor=PANEL_2,
                        insertcolor=TEXT, padding=(6, 4))
        style.map("Dark.TSpinbox",
                  fieldbackground=[("focus", PANEL_2)],
                  bordercolor=[("focus", ACCENT)])

        self.root.option_add("*TCombobox*Listbox.background", PANEL_2)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")
        self.root.option_add("*TCombobox*Listbox.font", (FONT, 9))

    def _set_titlebar_dark(self):
        try:
            self.root.update_idletasks()
            hwnd = user32.GetParent(self.root.winfo_id())
            dwmapi = ctypes.WinDLL("dwmapi")
            value = ctypes.c_int(1)
            dwmapi.DwmSetWindowAttribute(wintypes.HWND(hwnd), 20,
                                         ctypes.byref(value), ctypes.sizeof(value))
        except Exception:
            pass

    # ---------------- 界面搭建 ----------------

    def _build_ui(self):
        root = self.root
        root.configure(bg=BG)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)

        # --- 顶部标题区 ---
        header = tk.Frame(root, bg=BG, height=78)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)

        logo = tk.Canvas(header, width=44, height=44, bg=BG, highlightthickness=0)
        logo.pack(side="left", padx=(22, 14), pady=(16, 0))
        round_rect(logo, 1, 1, 43, 43, 12, fill="#1D2531", outline="#2C3746")
        logo.create_rectangle(11, 27, 16, 38, fill=ACCENT, width=0)
        logo.create_rectangle(19, 21, 24, 38, fill="#FF8892", width=0)
        logo.create_rectangle(27, 14, 32, 38, fill=CYAN, width=0)
        logo.create_line(10, 12, 33, 12, fill="#44506B", width=1)

        title_box = tk.Frame(header, bg=BG)
        title_box.pack(side="left", pady=(18, 0))
        tk.Label(title_box, text="游戏优先级优化", bg=BG, fg=TEXT,
                 font=(FONT, 15, "bold")).pack(anchor="w")
        tk.Label(title_box, text="反作弊进程降优先级  ·  游戏进程提优先级",
                 bg=BG, fg=MUTED, font=(FONT, 8)).pack(anchor="w")

        right = tk.Frame(header, bg=BG)
        right.pack(side="right", padx=22, pady=(18, 0))
        if self.no_admin:
            self.admin_btn = RoundButton(right, "以管理员重启", command=lambda: relaunch_as_admin(),
                                         width=112, height=26, fill="#3A1D22",
                                         hover="#4E262D", fg="#FF9AA2",
                                         font=(FONT, 8, "bold"), bg=BG, radius=13)
            self.admin_btn.pack(anchor="e")
            tk.Label(right, text="未提权 · 部分进程可能改不动", bg=BG, fg="#8A6570",
                     font=(FONT, 7)).pack(anchor="e", pady=(4, 0))
        else:
            Pill(right, "管理员模式", fg="#8FF0C4", fill="#12281F",
                 dot=GREEN, font=(FONT, 8)).pack(anchor="e")

        self.state_pill = Pill(right, "已停止", fg=MUTED, fill=PANEL_2,
                               dot="#44506B", font=(FONT, 8))
        self.state_pill.pack(anchor="e", pady=(6, 0))

        GradientBar(root, height=2).grid(row=0, column=0, sticky="sew")

        # --- 工具栏 ---
        bar = tk.Frame(root, bg=BG)
        bar.grid(row=1, column=0, sticky="ew", padx=22, pady=(12, 10))

        self.btn_start = RoundButton(bar, "▶  开始守卫", command=self.toggle_guard,
                                     width=132, height=36, fill=ACCENT,
                                     hover=ACCENT_DARK, font=(FONT, 9, "bold"))
        self.btn_start.pack(side="left")

        RoundButton(bar, "立即优化一次", command=self.manual_optimize,
                    width=118, height=36, fill=PANEL_2, hover=PANEL_3,
                    fg="#C9D3DF", font=(FONT, 9)).pack(side="left", padx=(10, 0))

        RoundButton(bar, "恢复默认", command=self.restore_default,
                    width=94, height=36, fill=PANEL, hover=PANEL_2,
                    fg=MUTED, font=(FONT, 9)).pack(side="left", padx=(8, 0))

        # 右侧参数
        ctrl = tk.Frame(bar, bg=BG)
        ctrl.pack(side="right")
        tk.Label(ctrl, text="反作弊", bg=BG, fg=MUTED, font=(FONT, 8)).pack(side="left")
        self.ace_combo = ttk.Combobox(ctrl, width=8, state="readonly",
                                      style="Dark.TCombobox",
                                      values=["最低", "低于正常"],
                                      font=(FONT, 9))
        self.ace_combo.pack(side="left", padx=(6, 16))
        self.ace_combo.set(PRIORITY_LABEL.get(self.cfg["ace_target"], "最低"))
        self.ace_combo.bind("<<ComboboxSelected>>", self._on_ace_change)

        tk.Label(ctrl, text="游戏", bg=BG, fg=MUTED, font=(FONT, 8)).pack(side="left")
        self.game_combo = ttk.Combobox(ctrl, width=10, state="readonly",
                                       style="Dark.TCombobox",
                                       values=["高于正常", "高", "实时（慎用）"],
                                       font=(FONT, 9))
        self.game_combo.pack(side="left", padx=(6, 16))
        self.game_combo.set(PRIORITY_LABEL.get(self.cfg["game_target"], "高"))
        self.game_combo.bind("<<ComboboxSelected>>", self._on_game_change)

        tk.Label(ctrl, text="扫描间隔", bg=BG, fg=MUTED, font=(FONT, 8)).pack(side="left")
        self.interval_var = tk.IntVar(value=int(self.cfg["interval"]))
        spin = ttk.Spinbox(ctrl, from_=1, to=60, width=4, textvariable=self.interval_var,
                           style="Dark.TSpinbox", command=self._on_interval_change,
                           font=(FONT, 9))
        spin.pack(side="left", padx=(6, 4))
        spin.bind("<FocusOut>", lambda _e: self._on_interval_change())
        tk.Label(ctrl, text="秒", bg=BG, fg=MUTED, font=(FONT, 8)).pack(side="left")

        # --- 主体：双列表 ---
        body = tk.Frame(root, bg=BG)
        body.grid(row=2, column=0, sticky="nsew", padx=22)
        body.columnconfigure(0, weight=1, uniform="col")
        body.columnconfigure(1, weight=1, uniform="col")
        body.rowconfigure(0, weight=1)

        self.ace_panel = ListPanel(body, "反作弊进程", "自动降低优先级，减少后台扫描占用",
                                   AMBER, on_add=self.add_custom_ace)
        self.ace_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        self.game_panel = ListPanel(body, "游戏进程", "自动提升优先级，优先获得 CPU 时间片",
                                    GREEN, on_add=self.add_custom_game)
        self.game_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        # --- 日志 ---
        log_box = tk.Frame(root, bg=PANEL, highlightthickness=1,
                           highlightbackground=BORDER)
        log_box.grid(row=3, column=0, sticky="ew", padx=22, pady=(12, 0))

        log_head = tk.Frame(log_box, bg=PANEL)
        log_head.pack(fill="x", padx=14, pady=(8, 2))
        tk.Label(log_head, text="运行日志", bg=PANEL, fg=TEXT,
                 font=(FONT, 9, "bold")).pack(side="left")
        clear_btn = tk.Label(log_head, text="清空", bg=PANEL, fg=MUTED,
                             font=(FONT, 8), cursor="hand2")
        clear_btn.pack(side="right")
        clear_btn.bind("<Button-1>", lambda _e: self._clear_log())
        clear_btn.bind("<Enter>", lambda _e: clear_btn.configure(fg=TEXT))
        clear_btn.bind("<Leave>", lambda _e: clear_btn.configure(fg=MUTED))

        log_inner = tk.Frame(log_box, bg=PANEL)
        log_inner.pack(fill="both", expand=True, padx=(10, 6), pady=(0, 8))

        self.log = tk.Text(log_inner, height=5, wrap="word", bg=PANEL, fg="#B9C4D1",
                           insertbackground=TEXT, bd=0, highlightthickness=0,
                           padx=6, pady=4, state="disabled",
                           font=(MONO, 9), spacing1=1, spacing3=2)
        self.log.pack(side="left", fill="both", expand=True)
        self.log.tag_config("time", foreground="#4E5A6B")
        self.log.tag_config("info", foreground="#8AB4F8")
        self.log.tag_config("ok", foreground=GREEN)
        self.log.tag_config("warn", foreground=AMBER)
        self.log.tag_config("err", foreground=RED)
        self.log.tag_config("muted", foreground=MUTED)

        # --- 状态栏 ---
        status = tk.Frame(root, bg="#0A0D12", height=32,
                          highlightthickness=1, highlightbackground=BORDER)
        status.grid(row=4, column=0, sticky="ew")
        status.grid_propagate(False)

        self.stat_left = tk.Label(status, text="累计优化 0 次", bg="#0A0D12", fg=MUTED,
                                  font=(FONT, 8))
        self.stat_left.pack(side="left", padx=22)
        self.stat_mid = tk.Label(status, text="扫描 0 次 · 间隔 3 秒", bg="#0A0D12",
                                 fg="#4E5A6B", font=(FONT, 8))
        self.stat_mid.pack(side="left")
        self.stat_right = tk.Label(status, text="运行时长 00:00:00", bg="#0A0D12",
                                   fg="#4E5A6B", font=(FONT, 8))
        self.stat_right.pack(side="right", padx=22)

        self._tick()

    # ---------------- 启动行为 ----------------

    def _on_first_show(self):
        if self.cfg.get("auto_start", True):
            self.toggle_guard()
        else:
            self._run_once(apply=False)

    def _warn_no_admin(self):
        self.log_line("warn", "当前不是管理员权限：游戏/反作弊进程多半会提示「权限不足」")
        self.log_line("warn", "点右上角「以管理员重启」即可解决（游戏本体建议先退出再重启工具）")

    # ---------------- 运行控制 ----------------

    def toggle_guard(self):
        if self.running:
            self.stop_guard()
        else:
            self.start_guard()

    def start_guard(self):
        if self.running:
            return
        self.running = True
        self.start_time = self.start_time or time.time()
        self.stop_event.clear()
        self.worker = threading.Thread(target=self._loop, daemon=True)
        self.worker.start()
        self.btn_start.set_text("■  停止守卫", fill="#2A333F", hover="#343F4D", fg="#FF9AA2")
        self.state_pill.update_state("守卫运行中", fg="#8FF0C4", fill="#12281F", dot=GREEN)
        self.log_line("ok", f"守卫已启动，每 {self.cfg['interval']} 秒自动扫描一次")

    def stop_guard(self):
        if not self.running:
            return
        self.running = False
        self.stop_event.set()
        self.btn_start.set_text("▶  开始守卫", fill=ACCENT, hover=ACCENT_DARK, fg="#FFFFFF")
        self.state_pill.update_state("已停止", fg=MUTED, fill=PANEL_2, dot="#44506B")
        self.log_line("warn", "守卫已停止，进程优先级将保持当前状态（可用「恢复默认」还原）")

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                self._scan(apply=True)
            except Exception as exc:
                self.queue.put(("log", "err", f"扫描异常：{exc}"))
            self.stop_event.wait(max(1, int(self.cfg["interval"])))

    def _run_once(self, apply=True, restore=False):
        threading.Thread(target=self._scan, kwargs={"apply": apply, "restore": restore},
                         daemon=True).start()

    def _scan(self, apply=True, restore=False):
        result = perform_scan(self.cfg, self.cfg.get("custom_games", []),
                              self.cfg.get("custom_ace", []), apply=apply,
                              restore=restore)
        self.scan_count += 1
        self.queue.put(("scan", result))

    def manual_optimize(self):
        self.start_time = self.start_time or time.time()
        self.log_line("info", "手动执行一次优化…")
        self._run_once(apply=True)

    def restore_default(self):
        self.log_line("info", "正在把已识别的进程优先级恢复为「正常」…")
        self._run_once(apply=True, restore=True)

    # ---------------- 参数变更 ----------------

    def _on_game_change(self, _e=None):
        mapping = {"高于正常": ABOVE_NORMAL_PRIORITY_CLASS,
                   "高": HIGH_PRIORITY_CLASS,
                   "实时（慎用）": REALTIME_PRIORITY_CLASS}
        self.cfg["game_target"] = mapping.get(self.game_combo.get(), HIGH_PRIORITY_CLASS)
        save_config(self.cfg)
        self.log_line("info", f"游戏目标优先级已设为「{self.game_combo.get()}」")
        if REALTIME_PRIORITY_CLASS == self.cfg["game_target"]:
            self.log_line("warn", "「实时」会抢占大量系统资源，可能造成卡顿/音频爆音，建议改回「高」")

    def _on_ace_change(self, _e=None):
        mapping = {"最低": IDLE_PRIORITY_CLASS, "低于正常": BELOW_NORMAL_PRIORITY_CLASS}
        self.cfg["ace_target"] = mapping.get(self.ace_combo.get(), IDLE_PRIORITY_CLASS)
        save_config(self.cfg)
        self.log_line("info", f"反作弊目标优先级已设为「{self.ace_combo.get()}」")

    def _on_interval_change(self):
        try:
            value = int(self.interval_var.get())
        except Exception:
            return
        value = max(1, min(60, value))
        self.interval_var.set(value)
        if value != self.cfg["interval"]:
            self.cfg["interval"] = value
            save_config(self.cfg)
            self.log_line("info", f"扫描间隔已设为 {value} 秒")
            self.stat_mid.configure(text=f"扫描 {self.scan_count} 次 · 间隔 {value} 秒")

    # ---------------- 自定义进程 ----------------

    def add_custom_game(self):
        self._custom_dialog("添加自定义游戏进程", "custom_games",
                            "例如新版本改了名字：deltaforceclient-win64-shipping.exe")

    def add_custom_ace(self):
        self._custom_dialog("添加自定义反作弊进程", "custom_ace",
                            "例如：ace-guard client.exe（多个用逗号分隔）")

    def _custom_dialog(self, title, key, hint):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=BG)
        win.geometry("440x210")
        win.transient(self.root)
        win.resizable(False, False)

        tk.Label(win, text=title, bg=BG, fg=TEXT, font=(FONT, 11, "bold")).pack(
            anchor="w", padx=18, pady=(16, 4))
        tk.Label(win, text=hint, bg=BG, fg=MUTED, font=(FONT, 8),
                 wraplength=400, justify="left").pack(anchor="w", padx=18)

        entry = tk.Entry(win, bg=PANEL_2, fg=TEXT, insertbackground=TEXT,
                         relief="flat", font=(FONT, 10), width=42)
        entry.pack(padx=18, pady=(10, 6), ipady=6, fill="x")
        entry.focus_set()

        current = "，".join(self.cfg.get(key, []))
        if current:
            tk.Label(win, text=f"当前已添加：{current}", bg=BG, fg="#5D6B7D",
                     font=(FONT, 8), wraplength=400, justify="left").pack(
                anchor="w", padx=18)

        def _save():
            text = entry.get().replace("，", ",").replace("；", ",")
            items = [x.strip() for x in text.split(",") if x.strip()]
            if items:
                existing = self.cfg.get(key, [])
                for item in items:
                    if item.lower() not in [e.lower() for e in existing]:
                        existing.append(item)
                self.cfg[key] = existing
                save_config(self.cfg)
                self.log_line("info", f"已添加自定义进程：{', '.join(items)}")
                self._run_once(apply=False)
            win.destroy()

        btns = tk.Frame(win, bg=BG)
        btns.pack(pady=(12, 0), padx=18, fill="x")
        RoundButton(btns, "保存", command=_save, width=88, height=32,
                    fill=ACCENT, hover=ACCENT_DARK, font=(FONT, 9, "bold")).pack(side="right")
        RoundButton(btns, "取消", command=win.destroy, width=72, height=32,
                    fill=PANEL_2, hover=PANEL_3, fg=MUTED,
                    font=(FONT, 9)).pack(side="right", padx=(0, 8))

        win.bind("<Return>", lambda _e: _save())
        win.bind("<Escape>", lambda _e: win.destroy())

    # ---------------- 队列 / 刷新 ----------------

    def _poll_queue(self):
        try:
            while True:
                event = self.queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.root.after(120, self._poll_queue)

    def _handle_event(self, event):
        if event[0] == "log":
            self.log_line(event[1], event[2])
        elif event[0] == "scan":
            self._apply_result(event[1])

    def _apply_result(self, result):
        self.game_panel.update_rows(result["games"],
                                    "— 未检测到游戏进程，先启动游戏 —")
        self.ace_panel.update_rows(result["ace"],
                                   "— 未检测到反作弊进程 —")
        self.adjust_count += result["changed"]

        for row in result["games"] + result["ace"]:
            pid = row["pid"]
            old = self.last_status.get(pid)
            if old == row["status"]:
                continue
            self.last_status[pid] = row["status"]
            status = row["status"]
            if status in ("已提升", "已降低", "已恢复"):
                arrow = {"已提升": "提升", "已降低": "降低", "已恢复": "恢复"}[status]
                self.log_line("ok", f"{row['name']} (PID {pid}) 优先级 {arrow}为「{row['cur']}」")
            elif status == "权限不足":
                self.log_line("warn", f"{row['name']} (PID {pid}) 权限不足，改不动"
                                      "（请以管理员运行；受反作弊自保护的进程属正常现象）")
            elif status == "被重置":
                self.log_line("warn", f"{row['name']} (PID {pid}) 设置后又被重置，"
                                      "可能是反作弊自保护，下一轮会再次尝试")
            elif status == "状态受限":
                self.log_line("warn", f"{row['name']} (PID {pid}) 无法读取优先级，进程可能受保护")

        # 清理已退出进程的状态缓存
        alive = {row["pid"] for row in result["games"] + result["ace"]}
        for pid in list(self.last_status):
            if pid not in alive:
                self.last_status.pop(pid, None)

        self.stat_left.configure(text=f"累计优化 {self.adjust_count} 次")
        self.stat_mid.configure(text=f"扫描 {self.scan_count} 次 · 间隔 {self.cfg['interval']} 秒")

    def _tick(self):
        if self.start_time:
            elapsed = int(time.time() - self.start_time)
            text = f"运行时长 {elapsed // 3600:02d}:{elapsed // 60 % 60:02d}:{elapsed % 60:02d}"
        else:
            text = "运行时长 00:00:00"
        self.stat_right.configure(text=text)
        self._tick_job = self.root.after(1000, self._tick)

    def log_line(self, level, msg):
        self.log.configure(state="normal")
        self.log.insert("end", time.strftime("%H:%M:%S  "), "time")
        self.log.insert("end", msg + "\n", level)
        total = int(self.log.index("end-1c").split(".")[0])
        if total > 400:
            self.log.delete("1.0", f"{total - 400}.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ---------------- 退出 ----------------

    def on_close(self):
        self.stop_event.set()
        if self._tick_job:
            try:
                self.root.after_cancel(self._tick_job)
            except Exception:
                pass
        self.root.destroy()


# =================================================================
# 六、入口
# =================================================================

def main():
    if os.name != "nt":
        raise SystemExit("仅支持 Windows")

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

    if not is_admin():
        try:
            if load_config().get("auto_elevate", True) and relaunch_as_admin(silent=True):
                return
        except Exception:
            pass

    root = tk.Tk()
    root.title(APP_TITLE)

    # 图标（程序内绘制，避免额外资源文件）
    try:
        icon = tk.PhotoImage(width=32, height=32)
        icon.put("#141A22", to=(0, 0, 32, 32))
        icon.put(ACCENT, to=(6, 18, 11, 27))
        icon.put("#FF8892", to=(13, 13, 18, 27))
        icon.put(CYAN, to=(20, 8, 25, 27))
        root.iconphoto(True, icon)
    except Exception:
        pass

    screen_w, screen_h = root.winfo_screenwidth(), root.winfo_screenheight()
    w = min(1180, int(screen_w * 0.78))
    h = min(860, int(screen_h * 0.88))
    x = max(0, (screen_w - w) // 2)
    y = max(0, (screen_h - h) // 2 - 20)
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.minsize(980, 700)

    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
