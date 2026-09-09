# Drop-in Sigma rules for Downpour
#
# Anything you place here (`.json` or `.yml`/`.yaml`) is loaded by
# `sigma_engine.load_user_rules()` on the next engine start (or after
# `sigma_engine.reload_rules()`). Rules run against:
#   * live process command lines  (logsource: category: process_creation)
#   * PowerShell 4104 script text (logsource: category: ps_script)
#
# Standard Sigma rules from https://github.com/SigmaHQ/sigma (Detection Rule
# License 1.1) work as-is for the common field set: Image, CommandLine,
# ParentImage, User, ScriptBlockText — with the contains/startswith/endswith/re
# modifiers and and/or/not/'1 of sel*'/'all of them' conditions.
#
# Unsupported constructs (aggregation, correlation, exotic YAML) are skipped
# safely — the engine never raises on a bad rule file.
