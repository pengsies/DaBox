"""Attacker-side pickle stubs matching the Web service's `prefs` module.

Only the module and class names enter the pickle. The target reconstructs
these objects with its own state-hook implementations.
"""


class RememberedPrefs:
    pass


class JobTemplate:
    pass


class JobRunner:
    pass

