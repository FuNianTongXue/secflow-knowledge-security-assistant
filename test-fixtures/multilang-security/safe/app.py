import subprocess

from flask import request


def show_file() -> None:
    requested_name = request.args.get("name")
    subprocess.run(["/usr/bin/printf", "%s", requested_name], check=True)
