.PHONY: up down ps logs seed

up:
	docker compose -f deployments/docker-compose.yml up -d

down:
	docker compose -f deployments/docker-compose.yml down -v

ps:
	docker compose -f deployments/docker-compose.yml ps

logs:
	docker compose -f deployments/docker-compose.yml logs -f --tail=100

seed:
	psql postgres://app:example@localhost:5432/app -f deployments/db/seed/products.sql
