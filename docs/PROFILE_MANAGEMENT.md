# Profile management

The Profiles tab is the normal editing surface. It lists profiles dynamically and supports create, clone, rename, delete, inheritance, Boolean/scalar fields, comma/range VLAN input, and topology lists. Effective inherited values appear separately from editable local overrides, along with consuming checks.

Save validates the complete inheritance chain, writes a temporary file, flushes it, atomically replaces the profile, and creates a timestamped backup. Cycles and missing bases are rejected. Advanced YAML remains available for expert values; unsaved edits are guarded.

Topology lists are organizational assertions and require a network/security owner. Do not guess user-facing ports, uplinks, authorized trunks, access-layer links, or exceptions.

