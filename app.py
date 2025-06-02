# app.py

import os
import base64
from aiohttp import web
import asyncpg
import aioredis
from jinja2 import Environment, FileSystemLoader
import bcrypt
from jose import jwt, JWTError
import secrets

# Конфигурация
DB_URL = os.getenv("DB_URL", "postgres://user:password@db:5432/shortener?sslmode=disable")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost")
TEMPLATES_DIR = "templates"

# Генерация короткого ID
def generate_short_id(url: str, length: int = 6) -> str:
    import hashlib
    hash_obj = hashlib.shake_256(url.encode())
    return base64.urlsafe_b64encode(hash_obj.digest(length)).decode()[:length]

# Инициализация пула подключений к PostgreSQL
async def init_db(app):
    app["pool"] = await asyncpg.create_pool(dsn=DB_URL)
    app["redis"] = await aioredis.from_url(REDIS_URL)

# Сохранение URL в PostgreSQL
async def save_url(pool, short_id: str, original_url: str):
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO urls (short_id, original_url) VALUES ($1, $2) ON CONFLICT (short_id) DO NOTHING",
            short_id, original_url
        )

# Получение URL из БД или Redis
async def get_url(pool, redis, short_id: str):
    cached = await redis.get(f"url:{short_id}")
    if cached:
        return cached.decode()

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT original_url FROM urls WHERE short_id = $1", short_id)
        if not row:
            return None
        await redis.setex(f"url:{short_id}", 3600, row["original_url"])
        return row["original_url"]

# Получение всех URL
async def get_all_urls(pool):
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT short_id, original_url FROM urls ORDER BY created_at DESC")
        return [{"short_id": r["short_id"], "original_url": r["original_url"]} for r in rows]

# Обработчик формы — сокращение URL
async def shorten_form(request):
    data = await request.post()
    url = data.get("url")
    if not url or not url.startswith("http"):
        return web.Response(text="Некорректный URL", status=400)

    short_id = generate_short_id(url)
    await save_url(request.app["pool"], short_id, url)

    raise web.HTTPFound(location="/")

# Отображение главной страницы
async def index(request):
    urls = await get_all_urls(request.app["pool"])

    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    template = env.get_template("index.html")
    content = template.render(urls=urls)

    return web.Response(text=content, content_type="text/html")

# Редирект по короткому ID
async def redirect_url(request):
    short_id = request.match_info["short_id"]
    original_url = await get_url(request.app["pool"], request.app["redis"], short_id)
    if not original_url:
        return web.Response(text="URL не найден", status=404)
    return web.Response(status=307, headers={"Location": original_url})

# API: получить все URL в формате JSON
async def api_get_urls(request):
    urls = await get_all_urls(request.app["pool"])
    return web.json_response({"urls": urls})

# API: удалить URL
async def api_delete_url(request):
    short_id = request.match_info["short_id"]
    pool = request.app["pool"]
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM urls WHERE short_id = $1", short_id)
    return web.json_response({"status": "ok"})

# API: обновить URL
async def api_update_url(request):
    short_id = request.match_info["short_id"]
    data = await request.json()
    new_url = data.get("url")
    if not new_url:
        return web.json_response({"error": "Missing 'url'"}, status=400)

    pool = request.app["pool"]
    async with pool.acquire() as conn:
        await conn.execute("UPDATE urls SET original_url = $1 WHERE short_id = $2", new_url, short_id)
    return web.json_response({"status": "updated"})

# Создаём приложение
app = web.Application()
app.on_startup.append(init_db)

app.router.add_get("/", index)
app.router.add_post("/shorten", shorten_form)
app.router.add_get("/{short_id}", redirect_url)

# API маршруты
app.router.add_get("/api/urls", api_get_urls)
app.router.add_delete("/api/urls/{short_id}", api_delete_url)
app.router.add_put("/api/urls/{short_id}", api_update_url)
app.router.add_post("/register", register)
app.router.add_post("/login", login)


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    print(f"Сервер запущен по адресу http://{host}:{port}")
    web.run_app(app, host=host, port=port)

    # Настройки JWT
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    ALGORITHM = "HS256"


    # Хэширование пароля
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


    # Проверка пароля
    def verify_password(password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode(), hashed.encode())


    # Генерация токена
    def create_jwt_token(data: dict):
        return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


    # Получить юзера по имени
    async def get_user_by_username(pool, username):
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM users WHERE username = $1", username)
            return row


    # Маршрут регистрации
    async def register(request):
        data = await request.json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return web.json_response({"error": "Missing username or password"}, status=400)

        hashed = hash_password(password)
        try:
            async with request.app["pool"].acquire() as conn:
                await conn.execute("INSERT INTO users (username, password) VALUES ($1, $2)", username, hashed)
            return web.json_response({"status": "ok"})
        except asyncpg.UniqueViolationError:
            return web.json_response({"error": "User already exists"}, status=400)


# Маршрут входа
async def login(request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")

    user = await get_user_by_username(request.app["pool"], username)
    if not user or not verify_password(password, user["password"]):
        return web.json_response({"error": "Invalid credentials"}, status=401)

    token = create_jwt_token({"sub": username})
    return web.json_response({"token": token})


# Middleware для проверки токена
@web.middleware
async def auth_middleware(request, handler):
    protected_routes = ['/shorten', '/api/urls']
    if any(request.path.startswith(route) for route in protected_routes):
        token = request.headers.get('Authorization')
        if not token:
            return web.json_response({"error": "Missing token"}, status=401)
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            request["user"] = payload.get("sub")
            if not request["user"]:
                return web.json_response({"error": "Invalid token"}, status=401)
        except JWTError:
            return web.json_response({"error": "Invalid token"}, status=401)
    return await handler(request)


# Создаём приложение с middleware
app = web.Application(middlewares=[auth_middleware])








