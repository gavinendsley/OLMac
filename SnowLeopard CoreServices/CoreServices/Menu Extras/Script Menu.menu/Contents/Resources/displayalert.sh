#!/usr/bin/osascript

on run argv
tell application "System Events"
activate
display alert (item 1 of argv) message (item 2 of argv) as warning
end tell
end run
