.PHONY: scan-up scan-down scan-restart scan-logs scan-test

scan-build:
	cd scan-api && docker build -t scan-api .

scan-up:
	docker rm -f scan-api 2>/dev/null; docker run --name scan-api -p 8080:8080 scan-api

scan-down:
	docker stop scan-api && docker rm scan-api

scan-restart: scan-down scan-up

scan-logs:
	docker logs -f scan-api

scan-test:
	curl -s -X POST http://localhost:8080/api/score \
	  -H "Content-Type: application/json" \
	  -d '{"url":"https://cloudflare.com"}' | jq .

scan-test-deep:
	curl -s -X POST http://localhost:8080/api/score/deep \
	  -H "Content-Type: application/json" \
	  -d '{"url":"https://cloudflare.com"}' | jq .

scan-test-both:
	curl -s -X POST http://localhost:8080/api/score/both \
	  -H "Content-Type: application/json" \
	  -d '{"url":"https://cloudflare.com"}' | jq .
