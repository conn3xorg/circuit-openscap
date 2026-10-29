#!/usr/bin/env sh
# Runs on the host: starts one scan through the timer's service, then checks
# it wrote results, a report and a summary with passing rules, and that the
# rule in skip_rules was left out. CI pipes it in with podman exec.
set -eu
systemctl is-enabled conn3x-scap.timer
systemctl start conn3x-scap.service
d=/var/lib/conn3x-scap/latest
test -s "$d/arf.xml"
test -s "$d/report.html"
cat "$d/summary.txt"
[ "$(awk '$1 == "pass" { print $2 }' "$d/summary.txt")" -gt 0 ]
grep -A1 'idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login"' "$d/results.xml" | grep -q '<result>notselected</result>'
