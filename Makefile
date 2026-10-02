.PHONY: demo test lint serve

demo:   ## Replay the sample payloads (dry run)
	ops-triage replay

test:
	pytest -q

lint:
	ruff check .

serve:
	ops-triage serve
