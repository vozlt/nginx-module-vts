FRONT_DIR := front

.PHONY: front-install front-build front-dev front-clean

## Install frontend dependencies
front-install:
	cd $(FRONT_DIR) && npm install

## Build frontend for production (outputs to front/dist/)
front-build: front-install
	cd $(FRONT_DIR) && npm run build

## Start frontend dev server with API proxy
front-dev: front-install
	cd $(FRONT_DIR) && npm run dev

## Remove frontend build artifacts and dependencies
front-clean:
	rm -rf $(FRONT_DIR)/dist $(FRONT_DIR)/node_modules
