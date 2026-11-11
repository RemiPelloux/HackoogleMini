# REA workspace

- `rea/`: clone of github.com/morluto/rea (docs: `rea/docs/`). Not an investigation.
- `_template/`: skeleton copied for every new investigation. Edit it to change future ones.
- Every other folder is one investigation created from the template.

## "new rea : xx"

When the user writes `new rea : <name>` (any spacing/case), run
`./new-rea.sh <name>` from this directory, report the created path, then work inside
that folder following its own `CLAUDE.md`. If the user also names a target or question,
put the target in `target/` (copy, never move the original) and fill `notes/findings.md`.
