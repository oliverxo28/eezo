#!/usr/bin/env pwsh
# Per-crate test runner for Windows (PowerShell).
$ErrorActionPreference = "Stop"

$meta = cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
$workspaceIds = @($meta.workspace_members)
$packages = @()

foreach ($pkg in $meta.packages) {
  if ($workspaceIds -contains $pkg.id) {
    $packages += $pkg.name
  }
}

$failures = 0

foreach ($pkg in $packages) {
  Write-Host "::group::cargo test -p $pkg"
  try {
    cargo test -p $pkg --all-features --all-targets --color always
  } catch {
    Write-Host "::error title=Tests failed::$pkg"
    $failures += 1
  } finally {
    Write-Host "::endgroup::"
  }
}

if ($failures -gt 0) {
  Write-Error "One or more crates failed ($failures)."
  exit 1
} else {
  Write-Host "All crates passed."
}
