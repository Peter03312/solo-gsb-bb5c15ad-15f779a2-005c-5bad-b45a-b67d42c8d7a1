# ---- 构建阶段 ----
FROM node:20-alpine AS build
WORKDIR /app

# 优先拷贝依赖清单以利用层缓存
COPY package.json package-lock.json* ./
RUN npm ci || npm install

# 拷贝源码并在镜像构建期跑一遍确定性自检，避免把回归带进镜像
COPY . .
RUN npm test

# 构建静态产物
RUN npm run build

# ---- 运行阶段：nginx 托管 ----
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || exit 1
CMD ["nginx", "-g", "daemon off;"]
