
# Задание
### Описание задания

Написать gRPC сервис обертку над nmap с использованием следующего скрипта
https://github.com/vulnersCom/nmap-vulners и предлагаемого API:
```sh
syntax = "proto3";

package netvuln.v1;

service NetVulnService {

 rpc CheckVuln(CheckVulnRequest) returns (CheckVulnResponse)

}

message CheckVulnRequest {

 repeated string targets = 1; // IP addresses

 repeated int32 tcp_port = 2; // only TCP ports

}

 message CheckVulnResponse {
 repeated TargetsReuslt results = 1;

}

message TargetResult {

 string target = 1; // target IP

 repeated Service services = 2

}

message Service {

 string name = 1;

 string version = 2;

 int32 tcp_port = 3;

 repeated Vulnerability vulns = 4;

}

message {

 string identifier = 1;

 float cvss_score = 2;

}
```

Библиотеки:

  - ограничений нет

  - для nmap можно использовать https://github.com/Ullaakut/nmap

Минимальные конфигурации сервиса:

  - адрес сервиса

  - уровень логирования

Небольшая инфраструктура:

  - make build – запуск сборки

  - make lint – запуск линтера

  - make test – запуск тестов

## How use
Пример на ос ubuntu с использованием в виде клиента gRPC - "EVANS"

  - Установить библиотеку nmap
```sh
sudo apt install nmap
```
  - Установить клиент Evans https://github.com/ktr0731/evans
  - Собрать и запустить проект teststak
```sh
make build
make run
```
  - Запустить Evans следующей командой
```sh
evans {Путь proto file} -p {port} (например: ./evans ~/Programming/Go/testtask/proto/nmap.proto -p 8080) 
```
  - Вызвать метод 
```sh
call CheckVuln
```
 - Ввести host, port и ожидать результата

Пример работы:
![image](https://user-images.githubusercontent.com/38299755/226746872-6c265588-4d5e-4634-8c88-c137750f3409.png)
