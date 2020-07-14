SHELL := /bin/bash

mongodb:
	docker-compose up -d --build mongodb

clean:
	docker-compose down
	docker container prune -f
	docker image prune -a -f
	docker network prune -f
