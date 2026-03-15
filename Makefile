.PHONY: run install clean test

install:
	cd backend && uv venv .venv && . .venv/bin/activate && uv pip install -r requirements.txt
	cd frontend && npm install && npm run build

run:
	python run.py

test:
	cd backend && . .venv/bin/activate && python -m pytest tests/ -v

clean:
	rm -f backend/depgra.db*
	rm -rf frontend/dist
