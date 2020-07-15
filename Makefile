SHELL := /bin/bash

mongodb:
	docker-compose up -d --build mongodb

clean:
	docker-compose down
	docker container prune -f
	docker network prune -f
