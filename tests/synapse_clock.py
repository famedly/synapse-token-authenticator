# Synapse moved Clock from synapse.util.clock to synapse.util.
try:
    from synapse.util.clock import Clock
except ModuleNotFoundError:
    from synapse.util import Clock

__all__ = ["Clock"]
