.PHONY: start-floci stop-floci deploy audit clean all build-sample-app run-sample-app opa-demo-positive opa-demo-negative

start-floci:
	docker kill floci 2>/dev/null || true
	docker rm floci 2>/dev/null || true
	docker run --rm -d \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-p 4566:4566 \
		--name floci \
		floci/floci:latest

stop-floci:
	docker stop floci || true
	docker rm floci || true

deploy: start-floci
	cd terraform && if [ -d .terraform/providers-mirror ]; then terraform init -plugin-dir=.terraform/providers-mirror; else terraform init; fi && terraform apply -auto-approve

audit:
	./scripts/floci-security-audit.sh

clean: stop-floci

build-sample-app:
	docker build -t sample-app ./app

run-sample-app: build-sample-app
	docker stop sample-app || true
	docker rm sample-app || true
	docker run --rm -d -p 5000:5000 --name sample-app sample-app

all:
	$(MAKE) deploy
	$(MAKE) run-sample-app
	$(MAKE) audit

opa-demo-positive:
	bash scripts/opa-demo-positive.sh

opa-demo-negative:
	bash scripts/opa-demo-negative.sh

# Run both OPA demo scenarios together (uncomment to enable)
# opa-demo:
#	bash scripts/opa-demo-positive.sh
#	bash scripts/opa-demo-negative.sh
