# Convenience targets for the single-container Podman deployment.
#   make podman-build && make podman-run
# Works with `podman` (Linux/macOS, or Git-Bash/WSL on Windows). On a plain
# Windows PowerShell prompt, use the equivalent run-podman.ps1 script instead.

IMAGE     ?= cxcreditguard:podman
CONTAINER ?= cxcreditguard
VOLUME    ?= cxcreditguard-data
PORT      ?= 8000

.PHONY: podman-build podman-run podman-port podman-logs podman-down podman-purge

podman-build:
	podman build -f deploy/podman/Dockerfile -t $(IMAGE) .

podman-run: podman-build
	-podman volume create $(VOLUME)
	-podman rm -f $(CONTAINER)
	podman run -d --name $(CONTAINER) --restart unless-stopped \
		-p $(PORT):8000 \
		-v $(VOLUME):/app/data \
		$(IMAGE)
	sleep 3
	podman logs --tail 60 $(CONTAINER)

podman-port:
	echo "UI:      http://localhost:$(PORT)"
	echo "API:     http://localhost:$(PORT)/api"
	echo "Docs:    http://localhost:$(PORT)/docs"
	echo "Health:  http://localhost:$(PORT)/healthz"

podman-logs:
	podman logs -f $(CONTAINER)

podman-down:
	-podman rm -f $(CONTAINER)

podman-purge: podman-down
	-podman volume rm -f $(VOLUME)