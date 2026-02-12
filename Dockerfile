# Multi-stage Dockerfile for Shrike MCP Server
# Adapted from backend/Dockerfile pattern (multi-stage, non-root)

# Stage 1: Builder
FROM node:20-alpine AS builder

WORKDIR /build

# Copy package files first for layer caching
COPY package.json package-lock.json ./

# Install all dependencies (including devDependencies for build)
RUN npm ci

# Copy source
COPY tsconfig.json ./
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Stage 2: Runtime
FROM node:20-alpine

# Security: run as non-root
RUN addgroup -g 65534 -S shrike && \
    adduser -u 65534 -S shrike -G shrike

WORKDIR /app

# Copy package files and install production deps only
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy built output from builder
COPY --from=builder /build/dist ./dist

# Set ownership
RUN chown -R shrike:shrike /app

USER shrike

# Default: stdio transport (MCP standard)
# Set MCP_TRANSPORT=http for HTTP mode (requires SDK upgrade)
ENV NODE_ENV=production

ENTRYPOINT ["node", "dist/index.js"]
