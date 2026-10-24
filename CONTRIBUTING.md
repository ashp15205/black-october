# Contributing

1. Keep each skill narrow: one problem, one `SKILL.md` (<500 lines), optional `scripts/` and `assets/`.
2. Any script change needs a unit test in `tests/test_scripts.py` and, for behaviour users rely on, an eval case in `evals/evals.json`.
3. Run before opening a PR:
   ```bash
   pip install -r requirements.txt
   python -W error::ResourceWarning -m unittest tests.test_scripts
   python tests/mutation_check.py
   python evals/run_evals.py
   python scripts/quick_validate.py
   python skills/security-config-code-review/scripts/scan.py . --exclude tests --fail-on HIGH
   ```
4. Never commit real secrets, real customer data or token-shaped literals; build fixtures at runtime (see `tests/fixtures.py`).
5. Security-relevant facts (deadlines, versions, exploitation status) must be looked up, not hardcoded.
