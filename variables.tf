variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file, jump_hosts or os."

  validation {
    condition     = alltrue([for h in var.hosts : contains(["debian", "ubuntu", "rocky", "fedora"], try(h.os, "debian"))])
    error_message = "A host object's os must be one of debian, ubuntu, rocky or fedora."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}

variable "profile" {
  type        = string
  default     = "cis_level1_server"
  description = "Profile to scan against: cis_level1_server, cis_level2_server, stig or standard, which the circuit maps to each distribution's own profile ID, or any profile ID in the host's content, such as \"anssi_bp28_high\"."

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+$", var.profile))
    error_message = "profile is a profile name such as \"cis_level1_server\", or a profile ID such as \"xccdf_org.ssgproject.content_profile_stig\"."
  }
}

variable "content_version" {
  type        = string
  default     = "0.1.82"
  description = "SCAP Security Guide release from ComplianceAsCode to scan with on Ubuntu, Debian and Fedora. Rocky Linux uses its own scap-security-guide package."

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.content_version))
    error_message = "content_version is a release number such as \"0.1.82\"."
  }
}

variable "content_sha256" {
  type        = string
  default     = "765e84bdce7f9055f9b9c2dd0ee2b713d4255f8eec94eac6d35ea4973c28919c"
  description = "SHA-256 of scap-security-guide-<content_version>.zip. Change it with content_version."

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.content_sha256))
    error_message = "content_sha256 is a SHA-256 in lowercase hex."
  }
}

variable "schedule" {
  type        = string
  default     = "Sun 03:00"
  description = "When the scan timer runs, as a systemd OnCalendar expression such as \"Sun 03:00\" or \"daily\". null leaves out the timer."

  validation {
    condition     = var.schedule == null || !strcontains(coalesce(var.schedule, "-"), "\n")
    error_message = "schedule is a single-line systemd calendar expression."
  }
}

variable "keep" {
  type        = number
  default     = 8
  description = "Number of scans to keep under /var/lib/conn3x-scap. Older ones are deleted after each scan."

  validation {
    condition     = var.keep >= 1 && floor(var.keep) == var.keep
    error_message = "keep must be a whole number, 1 or more."
  }
}

variable "run_now" {
  type        = bool
  default     = false
  description = "Scan during the apply: on the first apply, and again whenever the scan's settings change. A scan takes minutes."
}

variable "skip_rules" {
  type        = list(string)
  default     = []
  description = "Rules to leave out of the profile, by ID, such as [\"sshd_disable_root_login\"]. The circuit writes a tailoring file that turns them off."

  validation {
    condition     = alltrue([for r in var.skip_rules : can(regex("^[A-Za-z0-9_.-]+$", r))])
    error_message = "Each of skip_rules is a rule ID, such as \"sshd_disable_root_login\" or \"xccdf_org.ssgproject.content_rule_sshd_disable_root_login\"."
  }
}

variable "tailoring" {
  type        = string
  default     = null
  description = "Contents of your own XCCDF tailoring file, such as file(\"tailoring.xml\"). Set profile to the ID of the tailored profile in it. Can't be used with skip_rules."

  validation {
    condition     = var.tailoring == null || length(var.skip_rules) == 0
    error_message = "Use either skip_rules or tailoring, not both. Put the rules to skip in your tailoring file."
  }
}

variable "remediate" {
  type        = bool
  default     = false
  description = "Fix what the profile finds, once per host and profile. This changes SSH, PAM, the firewall and more. Try it on a throwaway host first."
}
