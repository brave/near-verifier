.PHONY: help run test test-local test-local-again clean lint format check quality validate install review-pins codebuild-prod codebuild-staging pre-commit
help:
	@echo "near-tee-verifier"
	@echo ""
	@echo "Targets:"
	@echo "  review-pins        Review pin drift, approve, PR, verify on merge (ENV=prod|staging|both)"
	@echo "  run                Run CodeBuild locally"
	@echo "  codebuild-prod     Start the AWS CodeBuild verification against prod (MODEL=<id>, default z-ai/glm-5.3-flash)"
	@echo "  codebuild-staging  Start the AWS CodeBuild verification against staging (MODEL=<id>, default z-ai/glm-5.3-flash)"
	@echo "  test               Run the Python unit test suite"
	@echo "  test-local         Run a full verification locally without CodeBuild"
	@echo "  test-local-again   Same, reusing the previous run's setup (--skip-setup)"
	@echo "  validate           Validate buildspec.yml"
	@echo "  install            Install dependencies"
	@echo "  lint               Lint all code (shell + Python)"
	@echo "  format             Format Python code"
	@echo "  check              Run mypy, bandit and vulture"
	@echo "  quality            Run full quality suite (format, lint, type check, security)"
	@echo "  pre-commit         Run pre-commit hooks manually"
	@echo "  clean              Clean generated files"
	@echo ""

install:
	poetry install

review-pins:
	poetry run python scripts/review_pins.py $(if $(ENV),--env $(ENV),)

run:
	./scripts/run-codebuild-local.sh -v

# Marketplace model id the CodeBuild run verifies (one model per run).
MODEL ?= z-ai/glm-5.3-flash

# Brave maintainers only: the CodeBuild project and aws-vault profile are internal.
CODEBUILD_PROJECT ?=
AWS_VAULT_PROFILE ?=
_codebuild = $(if $(and $(CODEBUILD_PROJECT),$(AWS_VAULT_PROFILE)),\
	aws-vault exec $(AWS_VAULT_PROFILE) -- aws codebuild start-build \
		--project-name $(CODEBUILD_PROJECT),\
	$(error set CODEBUILD_PROJECT and AWS_VAULT_PROFILE (Brave maintainers only)))

codebuild-prod:
	$(_codebuild) \
		--environment-variables-override \
			name=MODEL_NAME,value=$(MODEL),type=PLAINTEXT

codebuild-staging:
	$(_codebuild) \
		--environment-variables-override \
			name=NEAR_ENV,value=staging,type=PLAINTEXT \
			name=MODEL_NAME,value=$(MODEL),type=PLAINTEXT

test:
	poetry run pytest

test-local:
	./test-local.sh -v

test-local-again:
	./test-local.sh -v --skip-setup

validate:
	poetry run python -c "import yaml; yaml.safe_load(open('buildspec.yml'))" && echo "✅ Valid YAML"

format:
	@echo "Formatting Python code..."
	poetry run ruff format .
	poetry run ruff check --fix .
	@echo "✅ Formatting complete"

lint:
	@echo "Linting shell scripts..."
	@for file in scripts/*.sh test-local.sh; do \
		if [ -f "$$file" ]; then \
			echo "  Checking $$file..."; \
			bash -n "$$file" || exit 1; \
		fi; \
	done
	@echo "✅ Shell syntax check passed"
	@echo ""
	@echo "Linting Python code..."
	poetry run ruff check .
	poetry run ruff format --check .
	@echo "✅ Python lint passed"

check:
	@echo "Running type checks..."
	poetry run mypy verifier tests
	@echo ""
	@echo "Running security scan..."
	poetry run bandit -r verifier/ -c pyproject.toml
	@echo ""
	@echo "Finding dead code..."
	poetry run vulture verifier/ scripts/ --min-confidence 80
	@echo "✅ All checks passed"

quality: format lint check test
	@echo "✅ Full quality check complete"

pre-commit:
	poetry run pre-commit run --all-files

# Leaves .env.local alone: it holds the user's API keys.
clean:
	@echo "Cleaning generated files..."
	rm -f .codebuild.env
	rm -f .codebuild-env-vars
	rm -rf output/
	rm -rf tmp/
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	rm -rf .mypy_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ Cleanup complete"

.DEFAULT_GOAL := help
