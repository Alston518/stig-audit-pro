# Check authoring

Every pack declares `check_pack_version`, `schema_version`, and `minimum_app_version`. Every check declares identity, origin, safe commands, a supported check type, typed scope/conditions, result mapping, and evidence behavior.

Object checks must choose `empty_scope_status`. Use `Error` when no objects means evidence/applicability could not be established, `Not_Applicable` only when absence is itself proven, and `Not_Reviewed` when organizational context is missing. Never use an empty collection as proof of compliance.

Regex is compiled at load. Condition commands must appear in `commands`. Profile references use `{{ key }}` or typed `profile_key` values and must resolve for every selected profile before collection starts. Use semantic parsers for VLAN sets and interface state; do not encode VLAN membership with a substring regex.

Set `control_origin` to `official`, `organizational`, `custom`, or `example`. Preserve `stig_id`, `group_id`, and `rule_id` separately from `custom_check_id`. Official totals include only controls whose `include_in_official_totals` is true.

