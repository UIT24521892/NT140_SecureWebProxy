# NT140 Secure Web Gateway Lab (spec §15). Compatible with GNU make 3.81 (macOS).
SHELL := /bin/bash
COMPOSE ?= docker compose
.DEFAULT_GOAL := help

# Targets whose task is not done yet call this and fail loudly.
todo = @echo "not implemented yet ($(1)), see plan.md §6" >&2; exit 1

.PHONY: help init build up down ps logs clean reconfigure tls-mode worktime icap-bypass \
        feeds test bench summary eval-fp capture shell-staff shell-guest shell-squid lint

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-14s %s\n", $$1, $$2}'

init: ## Create .env, empty feeds, work_hours.conf, certificates
	@scripts/init.sh

build: ## Build images
	$(COMPOSE) build

up: ## Start the lab and wait for health checks
	$(COMPOSE) up -d --build --wait

down: ## Stop the lab (keeps volumes)
	$(COMPOSE) down

ps: ## Show service status
	$(COMPOSE) ps

logs: ## Follow service logs (SVC=name to filter)
	$(COMPOSE) logs -f --tail=100 $(SVC)

clean: ## Stop the lab, delete volumes, logs and results (asks first)
	@read -r -p "Delete volumes, logs/ and results/? [y/N] " ans; [ "$$ans" = "y" ] || exit 1
	$(COMPOSE) down -v
	rm -rf logs results

reconfigure: ## Reload squid configuration
	$(COMPOSE) exec squid squid -k reconfigure

tls-mode: ## Switch SslBump mode: MODE=splice|bump|selective
	$(call todo,TLS-3)

worktime: ## Switch work hours ACL: MODE=real|always|never
	$(call todo,POL-4)

icap-bypass: ## ICAP fail-open/closed: MODE=on|off
	$(call todo,THR-4)

feeds: ## Download and normalise threat feeds, then reload squid
	$(call todo,THR-5)

test: ## Run tests (S=S5 for one scenario, P=P0 for a priority)
	@if [ ! -f tests/run_all.py ]; then echo "not implemented yet (THR-2), see plan.md §6" >&2; exit 1; fi
	python3 tests/run_all.py $(if $(S),--scenario $(S)) $(if $(P),--priority $(P))

bench: ## Run benchmark B1-B8
	$(call todo,TLS-7)

summary: ## Summarise squid logs into results/
	$(call todo,THR-7)

eval-fp: ## Evaluate blocklist false positives against Tranco
	$(call todo,THR-8)

capture: ## Capture traffic: NAME=x SECS=30
	$(call todo,TLS-6)

shell-staff: ## Shell in client-staff
	$(COMPOSE) exec client-staff bash

shell-guest: ## Shell in client-guest
	$(COMPOSE) exec client-guest bash

shell-squid: ## Shell in squid
	$(COMPOSE) exec squid bash

lint: ## shellcheck + Python syntax check
	@scripts/lint.sh
