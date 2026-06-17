.PHONY: help list run run-docker test pytest clean

help:
	@echo "Sandbox agent security-control tests"
	@echo
	@echo "  make list         show backend availability and scenarios"
	@echo "  make run          run all scenarios on all available backends"
	@echo "  make run-docker   run all scenarios on the Docker backend only"
	@echo "  make pytest       run the pytest front-end (needs: pip install -r requirements.txt)"
	@echo "  make clean        remove caches"

list:
	python3 run_tests.py --list

run:
	python3 run_tests.py

run-docker:
	python3 run_tests.py --backend docker

pytest:
	pytest

clean:
	rm -rf .pytest_cache **/__pycache__ sandbox/__pycache__ sandbox/backends/__pycache__
