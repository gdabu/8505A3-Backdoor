import os
import subprocess

tmp = os.popen("ls").read()
proc = subprocess.Popen('ls', stdout=subprocess.PIPE)
tmp = proc.stdout.read()

print tmp