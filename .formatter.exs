# No `import_deps`: this app has no dependencies, and adding one here would be a
# dependency in everything but name (FR-001).
[
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"]
]
