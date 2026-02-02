# Makefile for Standard Linux Image
# Provides build, validation, and testing targets for Packer images

# ============================================================================
# Configuration
# ============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Directories
PROJECT_ROOT := $(shell pwd)
PACKER_DIR := $(PROJECT_ROOT)/packer
SCRIPTS_DIR := $(PROJECT_ROOT)/scripts
ANSIBLE_DIR := $(PROJECT_ROOT)/ansible
INSPEC_DIR := $(PROJECT_ROOT)/inspec/cis-benchmark
GOSS_DIR := $(PROJECT_ROOT)/goss
REPORTS_DIR := $(PROJECT_ROOT)/reports

# Packer configuration
PACKER_LOG ?= 0
PACKER_ON_ERROR ?= cleanup
export PACKER_LOG
export PACKER_ON_ERROR

# Build configuration
ROCKY_VERSION ?= 9
BUILD_VERSION ?= $(shell date +%Y%m%d)

# vSphere configuration (can be overridden via environment or .env file)
-include $(PROJECT_ROOT)/.env

# AWS configuration
AWS_REGION ?= us-east-1

# Validation configuration
CIS_THRESHOLD ?= 80
VALIDATION_REPORT_DIR ?= $(REPORTS_DIR)/validation-$(shell date +%Y%m%d-%H%M%S)

# Colors for output
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

# ============================================================================
# Help
# ============================================================================

.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "$(CYAN)Standard Linux Image - Build and Validation$(NC)"
	@echo ""
	@echo "$(YELLOW)Usage:$(NC)"
	@echo "  make <target> [VARIABLE=value ...]"
	@echo ""
	@echo "$(YELLOW)Initialization:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E '(init|setup)' | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Validation:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E '(validate|lint|check)' | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)vSphere Builds:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep 'vsphere' | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)AWS Builds:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep 'aws' | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Testing:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E '(test|inspec|goss)' | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Utilities:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -vE '(init|setup|validate|lint|check|vsphere|aws|test|inspec|goss)' | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Variables:$(NC)"
	@echo "  $(CYAN)ROCKY_VERSION$(NC)    Rocky Linux version (9 or 10, default: 9)"
	@echo "  $(CYAN)AWS_REGION$(NC)       AWS region for AMI builds (default: us-east-1)"
	@echo "  $(CYAN)CIS_THRESHOLD$(NC)    CIS compliance threshold (default: 80)"
	@echo "  $(CYAN)PACKER_LOG$(NC)       Enable Packer debug logging (0 or 1)"
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  make build-vsphere-9              # Build Rocky 9 vSphere template"
	@echo "  make build-aws-10 AWS_REGION=us-west-2"
	@echo "  make test-inspec TARGET=root@192.168.1.100"
	@echo ""

# ============================================================================
# Initialization
# ============================================================================

.PHONY: init
init: ## Initialize Packer plugins and dependencies
	@echo "$(CYAN)=== Initializing Packer Plugins ===$(NC)"
	cd $(PACKER_DIR) && packer init -upgrade .
	@echo "$(GREEN)Packer plugins initialized$(NC)"

.PHONY: setup
setup: init ## Complete project setup (init + directory creation)
	@echo "$(CYAN)=== Setting up project ===$(NC)"
	@mkdir -p $(REPORTS_DIR)
	@mkdir -p $(PACKER_DIR)/http
	@echo "$(GREEN)Project setup complete$(NC)"

.PHONY: install-validators
install-validators: ## Install InSpec and Goss validation tools
	@echo "$(CYAN)=== Installing Validation Tools ===$(NC)"
	sudo $(SCRIPTS_DIR)/install-validators.sh --verify --cleanup
	@echo "$(GREEN)Validation tools installed$(NC)"

# ============================================================================
# Packer Template Validation
# ============================================================================

.PHONY: validate-packer
validate-packer: ## Validate all Packer templates
	@echo "$(CYAN)=== Validating Packer Templates ===$(NC)"
	@ERRORS=0; \
	for template in $(PACKER_DIR)/*.pkr.hcl; do \
		echo "Validating $$template..."; \
		if packer validate -syntax-only "$$template" 2>/dev/null; then \
			echo "$(GREEN)  OK$(NC)"; \
		else \
			echo "$(RED)  FAILED$(NC)"; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
	done; \
	if [ $$ERRORS -gt 0 ]; then \
		echo "$(RED)Validation failed with $$ERRORS error(s)$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)All Packer templates are valid$(NC)"

.PHONY: validate-vsphere
validate-vsphere: ## Validate vSphere Packer template with variable checking
	@echo "$(CYAN)=== Validating vSphere Template ===$(NC)"
	cd $(PACKER_DIR) && packer validate \
		-var-file=variables.pkr.hcl \
		-var "vcenter_server=$${VCENTER_SERVER:-vcenter.example.com}" \
		-var "vcenter_username=$${VCENTER_USERNAME:-user}" \
		-var "vcenter_password=$${VCENTER_PASSWORD:-password}" \
		-var "vcenter_datacenter=$${VCENTER_DATACENTER:-dc}" \
		-var "vcenter_cluster=$${VCENTER_CLUSTER:-cluster}" \
		-var "vcenter_datastore=$${VCENTER_DATASTORE:-datastore}" \
		-var "vcenter_network=$${VCENTER_NETWORK:-network}" \
		-var "content_library_name=$${CONTENT_LIBRARY:-library}" \
		-var "ssh_password=$${SSH_PASSWORD:-packer}" \
		rocky-vsphere.pkr.hcl
	@echo "$(GREEN)vSphere template validation complete$(NC)"

.PHONY: validate-aws
validate-aws: ## Validate AWS Packer template
	@echo "$(CYAN)=== Validating AWS Template ===$(NC)"
	cd $(PACKER_DIR) && packer validate rocky-aws.pkr.hcl
	@echo "$(GREEN)AWS template validation complete$(NC)"

.PHONY: lint
lint: validate-packer ## Lint Packer templates (alias for validate-packer)

.PHONY: check
check: lint validate-ansible ## Run all validation checks

.PHONY: validate-ansible
validate-ansible: ## Validate Ansible playbooks
	@echo "$(CYAN)=== Validating Ansible Playbooks ===$(NC)"
	cd $(ANSIBLE_DIR) && ansible-playbook --syntax-check playbook.yml
	@echo "$(GREEN)Ansible validation complete$(NC)"

# ============================================================================
# vSphere Builds
# ============================================================================

.PHONY: build-vsphere-9
build-vsphere-9: init ## Build Rocky Linux 9 vSphere template
	@echo "$(CYAN)=== Building Rocky Linux 9 vSphere Template ===$(NC)"
	cd $(PACKER_DIR) && packer build \
		-var "rocky_version=9" \
		-var-file=variables.pkr.hcl \
		-on-error=$(PACKER_ON_ERROR) \
		rocky-vsphere.pkr.hcl
	@echo "$(GREEN)Rocky Linux 9 vSphere build complete$(NC)"

.PHONY: build-vsphere-10
build-vsphere-10: init ## Build Rocky Linux 10 vSphere template
	@echo "$(CYAN)=== Building Rocky Linux 10 vSphere Template ===$(NC)"
	cd $(PACKER_DIR) && packer build \
		-var "rocky_version=10" \
		-var-file=variables.pkr.hcl \
		-on-error=$(PACKER_ON_ERROR) \
		rocky-vsphere.pkr.hcl
	@echo "$(GREEN)Rocky Linux 10 vSphere build complete$(NC)"

.PHONY: build-vsphere
build-vsphere: build-vsphere-$(ROCKY_VERSION) ## Build vSphere template (uses ROCKY_VERSION)

# ============================================================================
# AWS Builds
# ============================================================================

.PHONY: build-aws-9
build-aws-9: init ## Build Rocky Linux 9 AMI
	@echo "$(CYAN)=== Building Rocky Linux 9 AMI ===$(NC)"
	cd $(PACKER_DIR) && packer build \
		-var "rocky_version=9" \
		-var "aws_region=$(AWS_REGION)" \
		-on-error=$(PACKER_ON_ERROR) \
		rocky-aws.pkr.hcl
	@echo "$(GREEN)Rocky Linux 9 AMI build complete$(NC)"

.PHONY: build-aws-10
build-aws-10: init ## Build Rocky Linux 10 AMI
	@echo "$(CYAN)=== Building Rocky Linux 10 AMI ===$(NC)"
	cd $(PACKER_DIR) && packer build \
		-var "rocky_version=10" \
		-var "aws_region=$(AWS_REGION)" \
		-on-error=$(PACKER_ON_ERROR) \
		rocky-aws.pkr.hcl
	@echo "$(GREEN)Rocky Linux 10 AMI build complete$(NC)"

.PHONY: build-aws
build-aws: build-aws-$(ROCKY_VERSION) ## Build AWS AMI (uses ROCKY_VERSION)

# ============================================================================
# All Builds
# ============================================================================

.PHONY: build-all-9
build-all-9: build-vsphere-9 build-aws-9 ## Build all Rocky Linux 9 images

.PHONY: build-all-10
build-all-10: build-vsphere-10 build-aws-10 ## Build all Rocky Linux 10 images

.PHONY: build-all
build-all: build-all-9 build-all-10 ## Build all images (Rocky 9 and 10)

# ============================================================================
# Testing - InSpec
# ============================================================================

.PHONY: test-inspec
test-inspec: ## Run InSpec CIS benchmark tests (TARGET=user@host for remote)
	@echo "$(CYAN)=== Running InSpec CIS Benchmark Tests ===$(NC)"
	@mkdir -p $(VALIDATION_REPORT_DIR)
ifdef TARGET
	@echo "Running against remote target: $(TARGET)"
	cd $(INSPEC_DIR) && inspec exec . \
		--target ssh://$(TARGET) \
		--reporter cli json:$(VALIDATION_REPORT_DIR)/inspec-results.json \
		--chef-license accept-silent || true
else
	@echo "Running locally"
	cd $(INSPEC_DIR) && sudo inspec exec . \
		--reporter cli json:$(VALIDATION_REPORT_DIR)/inspec-results.json \
		--chef-license accept-silent || true
endif
	@echo ""
	@echo "$(CYAN)Results saved to: $(VALIDATION_REPORT_DIR)/inspec-results.json$(NC)"
	@if [ -f "$(VALIDATION_REPORT_DIR)/inspec-results.json" ]; then \
		PASSED=$$(jq '[.profiles[0].controls[].results[] | select(.status == "passed")] | length' $(VALIDATION_REPORT_DIR)/inspec-results.json 2>/dev/null || echo 0); \
		FAILED=$$(jq '[.profiles[0].controls[].results[] | select(.status == "failed")] | length' $(VALIDATION_REPORT_DIR)/inspec-results.json 2>/dev/null || echo 0); \
		TOTAL=$$((PASSED + FAILED)); \
		if [ $$TOTAL -gt 0 ]; then \
			SCORE=$$((PASSED * 100 / TOTAL)); \
			echo "$(CYAN)Compliance Score: $$SCORE% ($$PASSED/$$TOTAL passed)$(NC)"; \
			if [ $$SCORE -lt $(CIS_THRESHOLD) ]; then \
				echo "$(RED)Score below threshold ($(CIS_THRESHOLD)%)$(NC)"; \
			else \
				echo "$(GREEN)Score meets threshold ($(CIS_THRESHOLD)%)$(NC)"; \
			fi; \
		fi; \
	fi

.PHONY: test-inspec-local
test-inspec-local: ## Run InSpec tests locally (requires root)
	@$(MAKE) test-inspec

.PHONY: test-inspec-remote
test-inspec-remote: ## Run InSpec tests against remote host (requires TARGET)
ifndef TARGET
	$(error TARGET is required. Usage: make test-inspec-remote TARGET=user@host)
endif
	@$(MAKE) test-inspec TARGET=$(TARGET)

# ============================================================================
# Testing - Goss
# ============================================================================

.PHONY: test-goss
test-goss: ## Run Goss server validation tests
	@echo "$(CYAN)=== Running Goss Server Validation ===$(NC)"
	@mkdir -p $(VALIDATION_REPORT_DIR)
	cd $(PROJECT_ROOT) && goss -g $(GOSS_DIR)/goss.yaml validate \
		--format documentation || true
	@echo ""
	cd $(PROJECT_ROOT) && goss -g $(GOSS_DIR)/goss.yaml validate \
		--format json > $(VALIDATION_REPORT_DIR)/goss-results.json 2>&1 || true
	@echo "$(CYAN)Results saved to: $(VALIDATION_REPORT_DIR)/goss-results.json$(NC)"

.PHONY: test-goss-render
test-goss-render: ## Render Goss test file (debug)
	@echo "$(CYAN)=== Rendering Goss Test File ===$(NC)"
	cd $(PROJECT_ROOT) && goss -g $(GOSS_DIR)/goss.yaml render

# ============================================================================
# Testing - Combined
# ============================================================================

.PHONY: test
test: test-goss test-inspec ## Run all tests (Goss and InSpec)

.PHONY: test-all
test-all: test ## Alias for test

.PHONY: validate-image
validate-image: ## Run comprehensive image validation
	@echo "$(CYAN)=== Running Comprehensive Image Validation ===$(NC)"
	$(SCRIPTS_DIR)/validate.sh \
		-r $(VALIDATION_REPORT_DIR) \
		-s $(CIS_THRESHOLD) \
		-f json
	@echo "$(GREEN)Validation complete. Reports at: $(VALIDATION_REPORT_DIR)$(NC)"

.PHONY: validate-remote
validate-remote: ## Validate remote image (requires TARGET)
ifndef TARGET
	$(error TARGET is required. Usage: make validate-remote TARGET=user@host)
endif
	@echo "$(CYAN)=== Running Remote Image Validation ===$(NC)"
	$(SCRIPTS_DIR)/validate.sh \
		-t $(TARGET) \
		-r $(VALIDATION_REPORT_DIR) \
		-s $(CIS_THRESHOLD) \
		-f json
	@echo "$(GREEN)Validation complete. Reports at: $(VALIDATION_REPORT_DIR)$(NC)"

# ============================================================================
# Reports
# ============================================================================

.PHONY: report
report: ## Generate validation summary report
	@echo "$(CYAN)=== Generating Validation Report ===$(NC)"
	@mkdir -p $(VALIDATION_REPORT_DIR)
	$(SCRIPTS_DIR)/validation-report.sh $(VALIDATION_REPORT_DIR)
	@echo "$(GREEN)Report generated$(NC)"

.PHONY: view-report
view-report: ## View the latest validation report
	@LATEST=$$(ls -td $(REPORTS_DIR)/validation-* 2>/dev/null | head -1); \
	if [ -n "$$LATEST" ] && [ -f "$$LATEST/validation-report.md" ]; then \
		cat "$$LATEST/validation-report.md"; \
	else \
		echo "No validation reports found"; \
	fi

# ============================================================================
# Cleanup
# ============================================================================

.PHONY: clean
clean: ## Clean build artifacts and temporary files
	@echo "$(CYAN)=== Cleaning Build Artifacts ===$(NC)"
	rm -rf $(PACKER_DIR)/packer_cache
	rm -f $(PACKER_DIR)/manifest-*.json
	rm -rf $(REPORTS_DIR)/validation-*
	rm -rf /tmp/validation-reports
	@echo "$(GREEN)Cleanup complete$(NC)"

.PHONY: clean-reports
clean-reports: ## Clean only validation reports
	@echo "$(CYAN)=== Cleaning Validation Reports ===$(NC)"
	rm -rf $(REPORTS_DIR)/validation-*
	@echo "$(GREEN)Reports cleaned$(NC)"

.PHONY: clean-all
clean-all: clean ## Deep clean including all generated files
	@echo "$(CYAN)=== Deep Cleaning ===$(NC)"
	rm -rf $(PACKER_DIR)/.packer.d
	rm -rf $(REPORTS_DIR)
	@echo "$(GREEN)Deep clean complete$(NC)"

# ============================================================================
# Development Helpers
# ============================================================================

.PHONY: shell
shell: ## Start interactive shell with environment loaded
	@echo "$(CYAN)Starting shell with project environment...$(NC)"
	@echo "Project root: $(PROJECT_ROOT)"
	@bash --rcfile <(echo "source ~/.bashrc; cd $(PROJECT_ROOT); export PS1='[packer-dev] \w $$ '")

.PHONY: fmt
fmt: ## Format Packer HCL files
	@echo "$(CYAN)=== Formatting Packer Files ===$(NC)"
	cd $(PACKER_DIR) && packer fmt -recursive .
	@echo "$(GREEN)Formatting complete$(NC)"

.PHONY: docs
docs: ## Generate documentation
	@echo "$(CYAN)=== Generating Documentation ===$(NC)"
	@echo "Documentation generation not yet implemented"

.PHONY: version
version: ## Show tool versions
	@echo "$(CYAN)=== Tool Versions ===$(NC)"
	@echo "Packer: $$(packer version 2>/dev/null || echo 'not installed')"
	@echo "Ansible: $$(ansible --version 2>/dev/null | head -1 || echo 'not installed')"
	@echo "InSpec: $$(inspec version 2>/dev/null || echo 'not installed')"
	@echo "Goss: $$(goss --version 2>/dev/null | head -1 || echo 'not installed')"

# ============================================================================
# CI/CD Helpers
# ============================================================================

.PHONY: ci-validate
ci-validate: validate-packer validate-ansible ## CI validation step

.PHONY: ci-build
ci-build: ci-validate build-all ## CI build step (validate + build all)

.PHONY: ci-test
ci-test: test ## CI test step

# ============================================================================
# Phony Targets Declaration
# ============================================================================

.PHONY: all
all: help
