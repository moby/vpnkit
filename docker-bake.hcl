group "default" {
  targets = ["bin-image"]
}

target "docker-metadata-action" {}

target "bin-image" {
  target = "binary"
  args = {
    BUILDKIT_CONTEXT_KEEP_GIT_DIR = 1
  }
  output = ["type=image"]
  platforms = [
    "linux/amd64",
    "linux/arm64",
  ]
}
