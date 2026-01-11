.PHONY: help install install-dev test lint format clean run scan

# Variables
PYTHON := python3
PIP := pip
PROJECT := secu-audit

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Installe les dépendances
	sudo $(PIP) install -r requirements.txt

install-dev: ## Installe les dépendances de développement
	sudo $(PIP) install -e ".[dev]"

test: ## Lance les tests unitaires
	pytest tests/ -v

test-cov: ## Lance les tests avec couverture
	pytest tests/ -v --cov=src/secu_audit --cov-report=html

lint: ## Vérifie le code avec flake8
	flake8 src/ tests/ --max-line-length=100

format: ## Formate le code avec black
	black src/ tests/ main.py

clean: ## Nettoie les fichiers temporaires
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	rm -f .coverage 2>/dev/null || true

run: ## Lance l'audit sur l'IP par défaut
	sudo $(PYTHON) main.py

scan: ## Lance l'audit sur une IP (usage: make scan IP=192.168.1.100)
	sudo $(PYTHON) main.py $(IP)

scan-network: ## Lance l'audit réseau (usage: make scan-network CIDR=192.168.1.0/24)
	sudo $(PYTHON) main.py $(CIDR)

build: ## Construit le package
	$(PYTHON) -m build

docker-cve: ## Lance CVE-Search Docker
	cd ~/CVE-Search-Docker && docker-compose up -d

docker-stop: ## Arrête CVE-Search Docker
	cd ~/CVE-Search-Docker && docker-compose down

documentation:
	doxygen Doxyfile