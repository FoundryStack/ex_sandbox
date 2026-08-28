import Config

# 005 T043: a real template list rather than `:any`, so `003`'s conformance
# check for `:template_missing` (`FR-027`) is actually exercised. With `:any`
# the mechanism would accept the suite's deliberately-bogus template name and
# the check would fail -- correctly, since a mechanism that invents a template
# on demand cannot report one missing.
#
# ⚠️ Only the one key, and the three timeouts from `config.exs` are deliberately
# NOT restated here.
#
# They were, until it was actually checked. `Config` DEEP-MERGES keyword values
# rather than replacing them -- MEASURED with `Config.Reader.read_imports!` on a
# two-line fixture: `[a: 1, b: 2]` then `[b: 99, c: 3]` yields
# `[a: 1, b: 99, c: 3]`. So restating them bought nothing and cost the usual
# price of a duplicated constant: two places to edit and no error if only one
# is.
config :ex_sandbox, :beam, templates: ["conformance-template", "t", "probe"]

# ⚠️ Load-bearing, and `RefusalLogTest` is what makes that visible. The egress
# denial path logs at `warning` deliberately -- an enforcement decision that
# leaves no record is indistinguishable from one that was never made -- and that
# test asserts BOTH halves: a `warning` survives this level, and an `info` does
# not. Without this line the level defaults to `:debug`, `info` survives, and the
# refutation fails while nothing about the library is wrong.
#
# Inherited from the umbrella's `config/test.exs` during extraction. It looked
# like ambient noise there; it is a test fixture.
config :logger, level: :warning
