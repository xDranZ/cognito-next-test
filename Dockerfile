# ---- deps ----
FROM node:20-alpine AS deps
WORKDIR /app

COPY package*.json ./
RUN npm ci


# ---- build ----
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

ARG NEXT_PUBLIC_COGNITO_DOMAIN
ARG NEXT_PUBLIC_COGNITO_CLIENT_ID
ARG NEXT_PUBLIC_COGNITO_REDIRECT_URI
ARG NEXT_PUBLIC_COGNITO_SCOPES
ARG NEXT_PUBLIC_COGNITO_LOGOUT_URI

ENV NEXT_PUBLIC_COGNITO_DOMAIN=$NEXT_PUBLIC_COGNITO_DOMAIN
ENV NEXT_PUBLIC_COGNITO_CLIENT_ID=$NEXT_PUBLIC_COGNITO_CLIENT_ID
ENV NEXT_PUBLIC_COGNITO_REDIRECT_URI=$NEXT_PUBLIC_COGNITO_REDIRECT_URI
ENV NEXT_PUBLIC_COGNITO_SCOPES=$NEXT_PUBLIC_COGNITO_SCOPES
ENV NEXT_PUBLIC_COGNITO_LOGOUT_URI=$NEXT_PUBLIC_COGNITO_LOGOUT_URI

RUN npm run build


# ---- runner ----
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public

EXPOSE 3000
CMD ["npm", "run", "start"]
