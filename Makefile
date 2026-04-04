REMOTE_HOST ?= user@bind-host.example.com
REMOTE_DIR  ?= /home/user/rpz-zone-factory

RSYNC_OPTS := -avz --delete --rsync-path=/usr/local/bin/rsync \
	--exclude='.git/' \
	--exclude='.venv/' \
	--exclude='.cache/' \
	--exclude='__pycache__/' \
	--exclude='*.pyc' \
	--exclude='.run-rpz.conf' \
	--exclude='allow-audit.log' \
	--exclude='*.rpz.db' \
	--exclude='*.rpz'

.PHONY: deploy

deploy:
	rsync $(RSYNC_OPTS) ./ $(REMOTE_HOST):$(REMOTE_DIR)/
