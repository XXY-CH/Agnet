FROM node:22-bookworm-slim

WORKDIR /app
COPY . .

CMD ["bash", "scripts/proof-demo.sh"]
