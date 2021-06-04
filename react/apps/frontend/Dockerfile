FROM node:16.3.0 as setup

RUN mkdir /app
ADD package.json* /app

WORKDIR /app

ENV NODE_PATH=/app/node_modules
ENV PATH=$PATH:/app/node_modules/.bin
RUN npm install

ADD . /app

FROM setup as dev
CMD ["npm", "start"]

FROM setup as build
RUN npm run build


FROM nginx:1.19.4-alpine AS prd

WORKDIR /usr/share/nginx/html

COPY --from=build /app/build /usr/share/nginx/html/admin

# Add Bash to make life easier.
RUN apk add --no-cache bash

ENTRYPOINT ["nginx", "-g", "daemon off;"]
