# Multi-stage Dockerfile for Shrike MCP Server
# Adapted from backend/Dockerfile pattern (multi-stage, non-root)

# Stage 1: Builder
FROM node:20-alpine AS builder

WORKDIR /build

# Copy package files first for layer caching
COPY package.json package-lock.json ./

# Install all dependencies (including devDependencies for build)
# --ignore-scripts: prevent "prepare" from running before source is copied
RUN npm ci --ignore-scripts

# Copy source
COPY tsconfig.json ./
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Stage 2: Runtime
FROM node:20-alpine

# Security: run as non-root
RUN addgroup -g 1001 -S shrike && \
    adduser -u 1001 -S shrike -G shrike

WORKDIR /app

# Copy package files and install production deps only
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# Copy built output from builder
COPY --from=builder /build/dist ./dist

# Set ownership
RUN chown -R shrike:shrike /app

USER shrike

# Default: stdio transport (MCP standard)
# Set MCP_TRANSPORT=http and MCP_PORT=8080 for Cloud Run HTTP mode
ENV NODE_ENV=production

ENTRYPOINT ["node", "dist/index.js"]
