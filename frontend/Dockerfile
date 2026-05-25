FROM node:24-alpine AS build

WORKDIR /frontend

ARG NPM_REGISTRY=https://package-mirror.liara.ir/repository/npm/

COPY package.json package-lock.json* ./
RUN npm config set registry "$NPM_REGISTRY" \
    && npm config set replace-registry-host always \
    && npm config set fetch-retries 5 \
    && npm config set fetch-retry-mintimeout 20000 \
    && npm config set fetch-retry-maxtimeout 120000 \
    && npm config set fetch-timeout 600000 \
    && npm ci --no-audit --no-fund

COPY . ./
RUN npm run build


FROM nginx:1.29-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /frontend/dist /usr/share/nginx/html

EXPOSE 8798
