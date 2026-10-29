output "results_dir" {
  description = "Directory on each host that holds one directory per scan, newest linked as latest."
  value       = local.results_dir
}

output "report" {
  description = "HTML report of the latest scan on each host."
  value       = "${local.results_dir}/latest/report.html"
}

output "results" {
  description = "ARF results of the latest scan on each host, for tools that read SCAP results."
  value       = "${local.results_dir}/latest/arf.xml"
}

output "profiles" {
  description = "Profile ID each host is scanned against."
  value       = local.profile
}
