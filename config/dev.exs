import Config

# Nothing to override. The defaults in `config.exs` are the developer-machine
# values already -- `System.tmp_dir!()` for the verdict socket because `/var/run`
# is not writable here, and `templates: :any` because there is no host registry
# to check against.
#
# Kept as a file rather than made conditional in `config.exs`: `import_config
# "#{config_env()}.exs"` is the conventional shape, and a reader who adds a dev
# override should find an obvious place to put it.
