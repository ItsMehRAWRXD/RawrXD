IMAGE ?= true:latest
PORT ?= 8080

.PHONY: build run stop push audit clean

build:
	docker build -t $(IMAGE) .

run:
	docker run --rm -p $(PORT):8080 --env-file .env -v $$PWD/uploads:/app/uploads $(IMAGE)

stop:
	docker stop true || true

push:
	docker push $(IMAGE)

audit:
	npm ci --omit=dev && npm audit --audit-level=high || true

clean:
	docker rmi $(IMAGE) || true
