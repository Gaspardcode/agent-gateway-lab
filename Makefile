# Usage : make test | make plan | make apply | make release | make publish | make tunnel | make ask | make redteam
# Identifiants : AWS_PROFILE=lab-admin (aws login --remote --profile lab-admin)
export AWS_PROFILE ?= lab-admin
export AWS_REGION  ?= eu-north-1
export PATH := $(HOME)/.local/bin:$(PATH)
AWS     ?= $(HOME)/.local/bin/aws
TF      := terraform -chdir=terraform
BACKEND ?= $(HOME)/aws-detection-lab/terraform/backend.hcl
PORT    := 8443
URL     := https://localhost:$(PORT)/v1/chat/completions
CURL    := curl -sS --cacert .pki/ca.crt --cert .pki/agent-support.crt --key .pki/agent-support.key

SHELL       := bash
.SHELLFLAGS := -eo pipefail -c

# Sorties Terraform lues DANS la recette, pas avec $(shell …) : GNU Make 4.3 ne
# transmet pas les variables exportées à $(shell), qui tournait donc sans
# AWS_PROFILE et renvoyait une chaîne vide en silence.
out = $$($(TF) output -raw $(1) 2>/dev/null || { echo "sortie Terraform '$(1)' illisible : session AWS expirée (aws login --remote --profile $(AWS_PROFILE)) ou make apply pas fait" >&2; exit 1; })
# Le tunnel doit être ouvert (make tunnel dans un autre terminal).
need_tunnel = ss -ltn | grep -q '127.0.0.1:$(PORT) ' || { echo "tunnel fermé : lancer 'make tunnel' dans un autre terminal" >&2; exit 1; }

# Dernière release construite, si V n'est pas donné.
V ?= $(lastword $(sort $(notdir $(wildcard dist/*))))

.PHONY: test lint init plan apply release publish tls up tunnel ask redteam stop start destroy status shell logs

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

publish:         ## signe avec KMS et envoie dans S3 (par défaut la dernière release de dist/)
	@[ -n "$(V)" ] || { echo "aucune release dans dist/ : make release" >&2; exit 1; }
	@echo "publication de $(V)"
	bucket=$(call out,release_bucket); key=$(call out,kms_key); \
	AWS=$(AWS) RELEASE_BUCKET=$$bucket KMS_KEY=$$key ./scripts/release.sh publish $(V)

tls:             ## pousse CA + certificat serveur dans SSM
	SSM_PREFIX=/agl/tls ./scripts/pki.sh push

up:              ## démarre l'instance si besoin et attend qu'elle tourne
	@id=$(call out,instance_id); \
	state=$$($(AWS) ec2 describe-instances --instance-ids $$id --query 'Reservations[0].Instances[0].State.Name' --output text); \
	if [ "$$state" != running ]; then \
	  echo "instance $$state, démarrage…"; \
	  $(AWS) ec2 start-instances --instance-ids $$id >/dev/null; \
	  $(AWS) ec2 wait instance-running --instance-ids $$id; \
	  echo "instance démarrée : compter 2-3 min avant que la passerelle réponde (make logs)"; \
	else echo "instance running"; fi

tunnel: up       ## https://localhost:8443 → passerelle (laisser tourner)
	@id=$(call out,instance_id); \
	until $(AWS) ssm describe-instance-information --filters Key=InstanceIds,Values=$$id \
	  --query 'InstanceInformationList[0].PingStatus' --output text | grep -q Online; do \
	  echo "agent SSM pas encore en ligne, nouvel essai dans 10 s…"; sleep 10; done; \
	echo "tunnel ouvert sur https://localhost:$(PORT) (Ctrl-C pour fermer)"; \
	$(AWS) ssm start-session --target $$id --document-name AWS-StartPortForwardingSession \
	  --parameters portNumber=$(PORT),localPortNumber=$(PORT)

ask:             ## question rapide : make ask Q="Bonjour" (tunnel ouvert)
	@$(need_tunnel)
	@[ -n "$(Q)" ] || { echo 'usage : make ask Q="ta question"' >&2; exit 1; }
	@$(CURL) $(URL) -H 'content-type: application/json' \
	  -d "$$(jq -n --arg q "$(Q)" '{messages: [{role: "user", content: $$q}], max_tokens: 300}')" \
	  | jq -r '.choices[0].message.content // .error.message // .'

redteam:         ## nécessite le tunnel ouvert
	@$(need_tunnel)
	python3 redteam/run.py --url $(URL) --pki .pki

stop:
	@$(AWS) ec2 stop-instances --instance-ids $(call out,instance_id) >/dev/null && echo arrêtée
start:
	@$(AWS) ec2 start-instances --instance-ids $(call out,instance_id) >/dev/null && echo démarrée

status:          ## état de l'instance, du tunnel et dernier événement de démarrage
	@id=$(call out,instance_id); \
	echo "instance : $$($(AWS) ec2 describe-instances --instance-ids $$id --query 'Reservations[0].Instances[0].State.Name' --output text)"; \
	if ss -ltn | grep -q '127.0.0.1:$(PORT) '; then echo "tunnel   : ouvert"; else echo "tunnel   : fermé"; fi; \
	echo "démarrage : $$($(AWS) logs tail $(call out,log_group) --log-stream-names boot --since 2h --format short | tail -1)"

shell:           ## shell sur l'instance, par SSM (pas de SSH)
	$(AWS) ssm start-session --target $(call out,instance_id)

logs:            ## audit de la passerelle en direct
	$(AWS) logs tail $(call out,log_group) --log-stream-names gateway boot --follow --format short

destroy:
	$(TF) destroy
