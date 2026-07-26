.PHONY: check test

check:
	python3 scripts/check-public-snapshot.py .
	python3 -m compileall -q panel scripts
	bash -n install.sh
	@for file in scripts/*.sh panel/*.sh; do [ ! -f "$$file" ] || bash -n "$$file"; done
	python3 -m unittest discover -s tests -p 'test_*.py'

test:
	python3 -m unittest discover -s tests -p 'test_*.py' -v
