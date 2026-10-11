package k8s.extra

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not regex.match(`^.+@sha256:[a-f0-9]{64}$`, c.image)
  msg := sprintf("container %q must pin its image by SHA-256 digest", [c.name])
}

warn contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  input.spec.template.spec.hostNetwork == true
  msg := sprintf("container %q should not share the host network namespace", [c.name])
}
