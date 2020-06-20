FROM node

WORKDIR /usr/src/app

COPY . .
EXPOSE 3000

RUN npm install && npm install typescript@latest -g
RUN tsc

CMD [ "npm", "start" ]