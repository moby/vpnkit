group "default" {
  targets = ["bin-image"]
}

target "docker-metadata-action" {}

target "bin-image" {
  target = "binary"
  output = ["type=image"]
  platforms = [
    "linux/amd64",
    "linux/arm64",
  ]
}
