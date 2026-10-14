# Usage : make test | make plan | make apply | make release | make publish V=<version> | make tunnel | make redteam
# Identifiants : AWS_PROFILE=lab-admin (aws login --remote --profile lab-admin)
export AWS_PROFILE ?= lab-admin
export AWS_REGION  ?= eu-north-1
AWS     ?= $(HOME)/.local/bin/aws
TF      := terraform -chdir=terraform
BACKEND ?= $(HOME)/aws-detection-lab/terraform/backend.hcl
OUT      = $(shell $(TF) output -raw $(1) 2>/dev/null)

.PHONY: test lint init plan apply release publish tls tunnel redteam stop start destroy status shell logs ask

test:            ## tests Rust (unitaires + bout en bout mTLS), dans Docker
	docker run --rm -v agw-cargo:/usr/local/cargo/registry -v $(CURDIR)/gateway:/src -w /src rust:1-bookworm cargo test --quiet

lint:
	$(TF) fmt -check -recursive
	$(TF) init -backend=false -input=false >/dev/null && $(TF) validate
	trivy config --quiet --exit-code 1 --ignorefile .trivyignore --severity HIGH,CRITICAL terraform
	bash -n scripts/*.sh && python3 -m py_compile agent/agent.py redteam/run.py

init:
	$(TF) init -input=false -backend-config=$(BACKEND)

plan: init
	$(TF) plan -out=agl.tfplan

apply:           ## applique le plan relu, jamais en aveugle
	$(TF) apply agl.tfplan

release:         ## construit dist/<version> (modèle vérifié + binaire statique + politique)
	./scripts/release.sh build

publish:         ## signe avec KMS et envoie dans S3 : make publish V=20261014-132518
	AWS=$(AWS) RELEASE_BUCKET=$(call OUT,release_bucket) KMS_KEY=$(call OUT,kms_key) ./scripts/release.sh publish $(V)

tls:             ## pousse CA + certificat serveur dans SSM
	PATH=$(dir $(AWS)):$$PATH SSM_PREFIX=/agl/tls ./scripts/pki.sh push

tunnel:          ## https://localhost:8443 → passerelle (laisser tourner)
	PATH=$(dir $(AWS)):$(HOME)/.local/bin:$$PATH $(call OUT,tunnel)

redteam:         ## nécessite le tunnel ouvert
	python3 redteam/run.py --url https://localhost:8443/v1/chat/completions --pki .pki

stop:
	$(AWS) ec2 stop-instances --instance-ids $(call OUT,instance_id) >/dev/null && echo arrêtée
start:
	$(AWS) ec2 start-instances --instance-ids $(call OUT,instance_id) >/dev/null && echo démarrée

status:          ## état de l'instance et du service de démarrage
	@$(AWS) ec2 describe-instances --instance-ids $(call OUT,instance_id) --query 'Reservations[0].Instances[0].State.Name' --output text

shell:           ## shell sur l'instance, par SSM (pas de SSH)
	PATH=$(dir $(AWS)):$$PATH $(AWS) ssm start-session --target $(call OUT,instance_id)

logs:            ## audit de la passerelle en direct
	$(AWS) logs tail $(call OUT,log_group) --log-stream-names gateway boot --follow --format short

ask:             ## question rapide : make ask Q="Bonjour" (tunnel ouvert)
	@curl -s --cacert .pki/ca.crt --cert .pki/agent-support.crt --key .pki/agent-support.key \
	  https://localhost:8443/v1/chat/completions -H 'content-type: application/json' \
	  -d "$$(jq -n --arg q "$(Q)" '{messages: [{role: "user", content: $$q}], max_tokens: 300}')" \
	  | jq -r '.choices[0].message.content // .error.message'

destroy:
	$(TF) destroy
