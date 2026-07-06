ARG AGNET_NODE_BASE_IMAGE=node:22-bookworm-slim
FROM ${AGNET_NODE_BASE_IMAGE}

WORKDIR /app
COPY . .

CMD ["bash", "scripts/proof-demo.sh"]
