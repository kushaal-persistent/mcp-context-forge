# Build stage: install dev dependencies explicitly (NODE_ENV=production would skip them).
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --include=dev
COPY . .
RUN npm test && npm run build

# Runtime stage: static files behind nginx, /api proxied to the gateway.
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
ENV GATEWAY_UPSTREAM=http://gateway:4444
EXPOSE 8080
