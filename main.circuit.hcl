# Facts give each host's distribution and release, which pick the content
# and the profile ID. The SCAP Security Guide builds one data stream per
# release, so a host it has no data stream for stops here.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = try(each.value.os, self.os_id) == self.os_id
      error_message = "Host ${each.key} is ${self.os_id}, not the ${try(each.value.os, "")} its os says."
    }
    postcondition {
      condition     = (self.os_id == "ubuntu" && self.os_version == "24.04") || (self.os_id == "debian" && self.os_version == "13") || (self.os_id == "rocky" && startswith(self.os_version, "10.")) || self.os_id == "fedora"
      error_message = "Host ${each.key} runs ${self.os_id} ${self.os_version}. This circuit supports Ubuntu 24.04, Debian 13, Rocky Linux 10 and Fedora."
    }
    postcondition {
      condition     = !contains(keys(local.profile_ids.ubuntu), var.profile) && !contains(keys(local.profile_ids.debian), var.profile) || contains(keys(lookup(local.profile_ids, self.os_id, {})), var.profile)
      error_message = "The SCAP Security Guide has no ${var.profile} profile for ${self.os_id}. Pick one of ${join(", ", keys(lookup(local.profile_ids, self.os_id, {})))}."
    }
  }
}

locals {
  # A host object's os stands in for the facts of a host created in the
  # same plan, which can't be read until it exists.
  os = { for name, h in var.hosts : name => try(h.os, data.conn3x_host.facts[name].os_id) }

  # The same benchmark has different profile IDs in each distribution's
  # content. These are the ones each data stream in 0.1.82 has.
  profile_ids = {
    ubuntu = { cis_level1_server = "cis_level1_server", cis_level2_server = "cis_level2_server", stig = "stig" }
    debian = { cis_level1_server = "cis_level1_server", cis_level2_server = "cis_level2_server", standard = "standard" }
    rocky  = { cis_level1_server = "cis_server_l1", cis_level2_server = "cis", stig = "stig" }
    fedora = { cis_level1_server = "cis_server_l1", cis_level2_server = "cis", standard = "standard" }
  }
  base_profile = {
    for name, o in local.os : name => startswith(var.profile, "xccdf_") ? var.profile : "xccdf_org.ssgproject.content_profile_${lookup(local.profile_ids[o], var.profile, var.profile)}"
  }

  # Upstream builds no Rocky Linux content: its RHEL 10 data stream checks
  # for the redhat-release package, so every rule is notapplicable on
  # Rocky. Rocky Linux's own scap-security-guide package adds an rl10 data
  # stream that knows Rocky. Ubuntu has no package, and Debian's is older,
  # so those and Fedora get the pinned release.
  package_hosts  = { for name, h in var.hosts : name => h if local.os[name] == "rocky" }
  upstream_hosts = { for name, h in var.hosts : name => h if local.os[name] != "rocky" }

  product = {
    for name, f in data.conn3x_host.facts : name => (
      f.os_id == "ubuntu" ? "ubuntu${replace(f.os_version, ".", "")}" :
      f.os_id == "debian" ? "debian${f.os_version}" :
      f.os_id == "rocky" ? "rl${split(".", f.os_version)[0]}" : f.os_id
    )
  }
  content_dir = "/usr/local/share/conn3x-scap/${var.content_version}"
  datastream = {
    for name, o in local.os : name => o == "rocky" ? "/usr/share/xml/scap/ssg/content/ssg-${local.product[name]}-ds.xml" : "${local.content_dir}/ssg-${local.product[name]}-ds.xml"
  }

  results_dir = "/var/lib/conn3x-scap"
  script      = "/usr/local/sbin/conn3x-scap"

  # skip_rules becomes a tailoring file whose profile extends the chosen one
  # with those rules turned off.
  tailored    = length(var.skip_rules) > 0
  tailoring   = "/etc/conn3x-scap/tailoring.xml"
  tailored_id = "xccdf_org.conn3x_profile_tailored"
  rule_ids    = [for r in var.skip_rules : startswith(r, "xccdf_") ? r : "xccdf_org.ssgproject.content_rule_${r}"]
  tailoring_xml = { for name, p in local.base_profile : name => <<-EOT
    <?xml version="1.0" encoding="UTF-8"?>
    <!-- Written by Conn3x. Changes here are overwritten on the next apply. -->
    <xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.conn3x_tailoring_skip_rules">
      <xccdf:version time="2026-01-01T00:00:00">1</xccdf:version>
      <xccdf:Profile id="${local.tailored_id}" extends="${p}">
        <xccdf:title>${p} without the rules in skip_rules</xccdf:title>
    %{for r in local.rule_ids~}
        <xccdf:select idref="${r}" selected="false"/>
    %{endfor~}
      </xccdf:Profile>
    </xccdf:Tailoring>
  EOT
  }
  profile = { for name, p in local.base_profile : name => local.tailored ? local.tailored_id : p }

  run_script = {
    for name, p in local.profile : name => <<-EOT
      #!/bin/sh
      # Written by Conn3x. Changes here are overwritten on the next apply.
      # Scans this host against ${p} and writes the results to a new
      # directory under ${local.results_dir}, then points latest at it.
      # Pass --remediate to fix what fails as well.
      set -u
      dir=${local.results_dir}
      run=$(date -u +%Y%m%dT%H%M%SZ)
      mkdir -p "$dir/$run"
      oscap xccdf eval "$@" \
        --profile ${p} \
        ${local.tailored || var.tailoring != null ? "--tailoring-file ${local.tailoring} " : ""}--results "$dir/$run/results.xml" \
        --results-arf "$dir/$run/arf.xml" \
        --report "$dir/$run/report.html" \
        ${local.datastream[name]} > "$dir/$run/oscap.log" 2>&1
      rc=$?
      # oscap exits 2 when the scan ran and some rules failed, which is what
      # a scan is for. Anything else is an error.
      if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
        tail -n 20 "$dir/$run/oscap.log" >&2
        exit "$rc"
      fi
      {
        grep -o 'score system="urn:xccdf:scoring:default"[^>]*>[0-9.]*' "$dir/$run/results.xml" | sed 's/.*>/score /'
        grep -o '<result>[a-z]*</result>' "$dir/$run/results.xml" | sed 's/<[^>]*>//g' | sort | uniq -c | awk '{print $2, $1}'
      } > "$dir/$run/summary.txt"
      ln -sfn "$run" "$dir/latest"
      find "$dir" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | head -n -${var.keep} | xargs -r rm -rf
      cat "$dir/$run/summary.txt"
    EOT
  }
}

circuit "content" {
  hosts = local.upstream_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "tools" {
    for_each = toset(["curl", "unzip"])
    package {
      name = item.value
    }
  }

  # The release zip unpacks to over 2 GB with every distribution's content,
  # so only this host's data stream is kept.
  step "datastream" {
    command {
      command = <<-EOT
        set -e
        tmp=$(mktemp -d)
        trap 'rm -rf "$tmp"' EXIT
        curl -sSfL -o "$tmp/ssg.zip" https://github.com/ComplianceAsCode/content/releases/download/v${var.content_version}/scap-security-guide-${var.content_version}.zip
        echo "${var.content_sha256}  $tmp/ssg.zip" | sha256sum -c --quiet
        unzip -q -j "$tmp/ssg.zip" scap-security-guide-${var.content_version}/ssg-${local.product[each.key]}-ds.xml -d "$tmp"
        install -D -m 644 "$tmp/ssg-${local.product[each.key]}-ds.xml" ${local.datastream[each.key]}
      EOT
      creates = local.datastream[each.key]
    }
  }
}

circuit "package" {
  hosts = local.package_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "content" {
    package {
      name = "scap-security-guide"
    }
  }
}

circuit "scap" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "scanner" {
    depends_on = [conn3x_command.content__datastream, conn3x_package.package__content]
    package {
      name = "openscap-scanner"
    }
  }

  # Fails the apply when the profile isn't in this host's content, before
  # anything else changes, rather than leaving a timer that fails every
  # week. oscap info exits 0 for a profile it can't find, so this searches
  # the list instead. A tailoring file of your own names its own profile,
  # which isn't in the list.
  step "profile_valid" {
    for_each = toset(var.tailoring == null ? ["profile"] : [])
    command {
      command = "oscap info --profiles ${local.datastream[each.key]} | grep -q '^${local.base_profile[each.key]}:' || { echo 'No profile ${local.base_profile[each.key]} in ${local.datastream[each.key]}. List them with: oscap info ${local.datastream[each.key]}' >&2; exit 1; }"
    }
  }

  step "config_dir" {
    directory {
      path = "/etc/conn3x-scap"
    }
  }

  # Reports list every weakness the host has, so only root reads them.
  step "results_dir" {
    directory {
      path = local.results_dir
      mode = "0700"
    }
  }

  step "tailoring" {
    for_each = toset(local.tailored || var.tailoring != null ? ["tailoring"] : [])
    file {
      path    = local.tailoring
      content = local.tailored ? local.tailoring_xml[each.key] : var.tailoring
    }
  }

  step "script" {
    file {
      path    = local.script
      content = local.run_script[each.key]
      mode    = "0755"
    }
  }

  step "schedule_valid" {
    for_each = toset(var.schedule == null ? [] : [var.schedule])
    command {
      command = "echo 'schedule is not a calendar expression systemd understands: ${item.value}' >&2; exit 1"
      unless  = "systemd-analyze calendar '${item.value}' >/dev/null"
    }
  }

  step "timer" {
    for_each = toset(var.schedule == null ? [] : ["timer"])
    timer {
      name        = "conn3x-scap"
      description = "OpenSCAP scan against ${var.profile}"
      on_calendar = var.schedule
      command     = local.script
      persistent  = true
    }
  }

  # Runs once per host and profile. The marker keeps it from running on
  # every apply; delete it to remediate again.
  step "remediate" {
    for_each = toset(var.remediate ? ["remediate"] : [])
    command {
      command = "${local.script} --remediate && date -u > ${local.results_dir}/remediated-${local.base_profile[each.key]}"
      creates = "${local.results_dir}/remediated-${local.base_profile[each.key]}"
    }
  }

  step "scan" {
    for_each = toset(var.run_now ? ["scan"] : [])
    command {
      command  = local.script
      triggers = { script = conn3x_file.scap__script[each.key].revision }
    }
  }
}
