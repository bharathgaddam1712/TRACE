PY ?= python3
VENV ?= .venv
BIN = $(VENV)/bin
INPUT ?= data/raw
OUT ?= out

.PHONY: setup test demo run serve web eval bench attack clean

setup:            ## create venv and install (Python >= 3.11)
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -r requirements-dev.txt
	$(BIN)/pip install --no-deps -e .

test:             ## complete unit and end-to-end suite
	$(BIN)/python -m pytest -q

demo:             ## sample + planted attack chain -> out/demo, then score it
	rm -rf data/demo && mkdir -p data/demo
	cp data/sample/edr_events.json data/demo/
	$(BIN)/tracekc plant --out data/planted
	cp data/planted/planted_chain.json data/demo/
	$(BIN)/tracekc run --input data/demo --out out/demo
	$(BIN)/tracekc eval --out out/demo --gt data/planted/planted_gt.json

run:              ## full pipeline: make run INPUT=data/raw OUT=out
	$(BIN)/tracekc run --input $(INPUT) --out $(OUT)

serve:            ## API + web page on :8000
	$(BIN)/tracekc serve --out $(OUT)

web:              ## Next.js console on :3000 (start `make serve` first)
	cd frontend && npm ci && npm run build && npm run start

eval:             ## score: make eval GT=path/to/ground_truth.json
	$(BIN)/tracekc eval --out $(OUT) --gt $(GT) --save $(OUT)/eval.json

bench:            ## build a synthetic tier and time it: make bench GB=15
	bash scripts/benchmark.sh $(GB)

attack:           ## download + verify the pinned ATT&CK v20.0 STIX bundle
	$(BIN)/python scripts/fetch_attack.py --version 20.0
	$(BIN)/tracekc attack-verify --stix attack/enterprise-attack-20.0.json

clean:
	rm -rf out work data/demo data/planted
