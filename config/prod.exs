import Config

# Deliberately empty.
#
# ⚠️ Production values are the OPERATOR's, not this library's. A gateway's boot
# timeout depends on its storage, and the verdict socket belongs wherever that
# host keeps runtime sockets -- guessing either here would ship a default that
# looks authoritative and is wrong for every deployment but the one it was
# written against.
#
# A consumer sets these in its own `config/`; this file exists so `config.exs`'s
# `import_config` resolves in every environment.
