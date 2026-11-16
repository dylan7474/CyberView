"""Manage portal users from the command line (run inside the app container; see ./deploy.sh users).

    users.py list
    users.py add NAME [--role viewer|editor|admin]   (default editor; asks for the password)
    users.py passwd NAME                             (sets a new password, which the user must change at next sign-in)
    users.py role NAME ROLE
    users.py disable NAME | enable NAME | unlock NAME
    users.py remove NAME

Roles: viewer = read only; editor = read + import/edit data; admin = also users, restore, reset, activity log.
While there are NO users the portal is open to everyone as administrator ("setup mode").
"""
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import app  # noqa: E402
from fastapi import HTTPException  # noqa: E402


def ask_password(name):
    pw = os.environ.get("USER_PASSWORD")
    if pw:
        return pw
    pw = getpass.getpass(f"Password for {name} (at least {app.MIN_PASSWORD} characters): ")
    if getpass.getpass("Again: ") != pw:
        raise SystemExit("Passwords differ")
    return pw


def main(argv):
    if len(argv) < 2 or argv[1] not in ("list", "add", "passwd", "role", "disable", "enable", "unlock", "remove"):
        print(__doc__)
        return 2
    cmd = argv[1]
    try:
        with app.conn_ctx() as c, c.cursor() as cur:
            if cmd == "list":
                cur.execute("SELECT username, role, disabled, last_login FROM users ORDER BY username")
                rows = cur.fetchall()
                if not rows:
                    print("(no users: the portal is OPEN to everyone as administrator)")
                for n, r, d, ll in rows:
                    print(f"{n:24} {r:8} {'DISABLED' if d else 'active':9} last sign-in: {ll or 'never'}")
                return 0
            if len(argv) < 3:
                print(__doc__)
                return 2
            name = argv[2]
            if cmd == "add":
                role = argv[argv.index("--role") + 1] if "--role" in argv else "editor"
                app.create_user(cur, name, ask_password(name), role, False)
                app.audit(cur, "cli", "user-added", f"{name} as {role}")
                print(f"Added {name} ({role}). Sign-in is now required for everyone.")
                return 0
            cur.execute("SELECT id, role FROM users WHERE username=%s FOR UPDATE", (name,))
            row = cur.fetchone()
            if not row:
                print(f"No user {name}")
                return 1
            uid, role = row
            if cmd == "passwd":
                pw = ask_password(name)
                app.validate_new_password(name, pw)
                cur.execute("UPDATE users SET pw_hash=%s, must_change=1, failed_attempts=0, locked_until=NULL WHERE id=%s", (app.hash_password(pw), uid))
                cur.execute("DELETE FROM sessions WHERE user_id=%s", (uid,))
            elif cmd == "role":
                if len(argv) < 4 or argv[3] not in app.RANK:
                    print("role must be viewer, editor or admin")
                    return 2
                if role == "admin" and argv[3] != "admin" and app.active_admins(cur, name) == 0:
                    print("That would leave no administrator")
                    return 1
                cur.execute("UPDATE users SET role=%s WHERE id=%s", (argv[3], uid))
                cur.execute("DELETE FROM sessions WHERE user_id=%s", (uid,))
            elif cmd in ("disable", "enable"):
                if cmd == "disable" and role == "admin" and app.active_admins(cur, name) == 0:
                    print("That would leave no administrator")
                    return 1
                cur.execute("UPDATE users SET disabled=%s WHERE id=%s", (1 if cmd == "disable" else 0, uid))
                cur.execute("DELETE FROM sessions WHERE user_id=%s", (uid,))
            elif cmd == "unlock":
                cur.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=%s", (uid,))
            elif cmd == "remove":
                if role == "admin" and app.active_admins(cur, name) == 0:
                    print("That would leave no administrator")
                    return 1
                cur.execute("DELETE FROM users WHERE id=%s", (uid,))
            app.audit(cur, "cli", f"user-{cmd}", name)
            print(f"{cmd}: {name} done.")
            return 0
    except HTTPException as e:
        print(e.detail)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
