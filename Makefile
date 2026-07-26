.PHONY: start-floci stop-floci deploy audit clean all

start-floci:
	docker run --rm -d \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-p 4566:4566 \
		-p 4510-4559:4510-4559 \
		--name floci \
		floci/floci:latest

stop-floci:
	docker stop floci || true
	docker rm floci || true

deploy: start-floci
	cd terraform && terraform init && terraform apply -auto-approve

audit:
	./scripts/floci-security-audit.sh

clean: stop-floci

all: deploy audit
