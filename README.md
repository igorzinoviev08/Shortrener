URL Shortener — сервис сокращения ссылок
Описание 

Простой сервис сокращения ссылок с использованием: 

    aiohttp — асинхронный веб-сервер
    asyncpg — работа с PostgreSQL
    redis-py — кэширование
    docker-compose — контейнеризация
     
Возможности 

    Сокращение URL
    Редирект по короткой ссылке
    Админка с удалением ссылок
    Авторизация через JWT

Установка 

# Запуск через Docker
bash
1 # Запуск через Docker
2 docker-compose up --build 



API 
POST
	
/register
	
Регистрация пользователя
POST
	
/login
	
Логин и получение токена
POST
	
/urls
	
Сокращение URL
GET
	
/{short_id}
	
Редирект
DELETE
	
/urls/{short_id}
	
Удаление ссылки
