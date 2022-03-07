FROM golang:1.16-alpine

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . ./

RUN GOOS=linux GOARCH=amd64 go build -o cmd ./generate-cve-csv
# RUN chmod a+x /cmd

CMD [ "./cmd" ]