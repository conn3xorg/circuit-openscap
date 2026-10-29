variable "port" {
  type    = number
  default = 2222
}

module "openscap" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  profile  = "cis_level1_server"
  schedule = "Sun 03:00"
  keep     = 4

  # Conn3x logs in as root, so keep the rules that would stop it.
  skip_rules = ["sshd_disable_root_login"]
}

output "report" {
  value = module.openscap.report
}
