# AGENTS.md

These instructions apply to this standalone `proxy-router` project.

## Project shape

- The main application is the root executable: `proxy-router`
- Keep the project lightweight and single-file unless a split is clearly necessary
- Prefer standard-library Python only

## Editing

- Preserve the current command name: `proxy-router`
- Keep dashboard/backend behavior in sync when changing config fields
- Prefer minimal, focused changes over broad refactors
- Use ASCII unless the file already needs something else

## Validation

- Run `python3 -m py_compile ./proxy-router`
- Run `python3 ./proxy-router --help`
- For container changes, run `docker compose config` when Docker is available

## Docker

- Use `docker compose`, not `docker-compose`
- Keep runtime data mounted under `./data`
- Do not bake secrets into the image or commit `.env`

## Docs

- Update `README.md` when changing dashboard flows, config structure, ports, Docker usage, or quota behavior
