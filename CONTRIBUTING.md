# Contributing

## Adding a Test

1. Pick the right category module in `agents/platform/darwin/`:
   - `credentials.sh` - Keys, tokens, secrets
   - `personal_data.sh` - User content (messages, contacts, history)
   - `system_visibility.sh` - System info (processes, users, network)
   - `persistence.sh` - Write access to sensitive locations

2. Follow the template in `agents/SKILL.md`

3. Use the `emit()` function:
   ```bash
   emit "category" "test_name" "status" "value" "severity"
   # status: exposed | blocked | not_found | error
   # severity: critical | high | medium | low
   ```

4. Add your test to `run_*_tests()` at the bottom of the module

5. Test it:
   ```bash
   SANDBOXSCORE_DEBUG=1 ./agents/run.sh 2>&1 | grep your_test
   ```

## Adding a Module

New modules go in `sandboxscore/<module>/` following the same structure as `agents/`.

1. Create `run.sh` entry point
2. Create `lib/common.sh` (or import shared library)
3. Create `platform/<os>/` test modules
4. Update root README.md module table

## Submitting

1. Fork the repo
2. Create a branch (`git checkout -b add-chrome-passwords-test`)
3. Make your changes
4. Test across profiles: `./agents/run.sh -p personal && ./agents/run.sh -p sensitive`
5. Open a PR with:
   - What the test probes
   - Why the severity level is appropriate
   - How you tested it

For bugs, open an issue first if you're unsure about the fix.

## Rules

- **Bash 3.2 compatible** - No associative arrays, no `${var,,}` syntax
- **Stats only** - Never emit actual content, only counts
- **Clean up** - Delete any test files immediately
- **Check prerequisites** - Verify HOME, commands exist before using
- **Use `to_int()`** - Sanitize all numeric values from external commands
